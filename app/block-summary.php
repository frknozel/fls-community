<?php
declare(strict_types=1);
require_once __DIR__.'/source-summary.php';

/** Counts original block records once; derived memberships supply their existing group identity. */
function block_summary(): array {
    [$from,$to]=scope();
    $kind=$_GET['block_scope']??'all';
    $outcomes=['all'=>null,'security'=>'security_block','policy'=>'policy_deny','local'=>'local_deny'];
    if(!is_string($kind) || !array_key_exists($kind,$outcomes))throw new InvalidArgumentException('Engel kapsamı geçersiz.');
    $names=[];foreach(query('SELECT policyid,name FROM '.fg_scoped_table('device_policies').' p ORDER BY policyid,name') as $p)$names[$p['policyid']][$p['name']]=true;
    $devices=[];foreach(query('SELECT ip,name FROM '.fg_scoped_table('device_sources').' d') as $d)$devices[$d['ip']]=$d['name'];
    $spool=new ReportRankingSpool();$rankings=[];foreach(['sources','policies','profiles','reasons'] as $dimension)$rankings[$dimension]=new ReportRanking($spool,false);$groups=new ReportRanking($spool,false);
    $totals=['records'=>0,'groups'=>0];$families=[];
    foreach(['security_block','policy_deny','local_deny'] as $o)$families[$o]=['outcome'=>$o,'records'=>0,'groups'=>0];
    $add=function(string $dimension,string $key,array $facts,int $n)use(&$rankings):void{
        $rankings[$dimension]->add($key,$facts,$n);
    };
    // Stream aggregated group/profile buckets: no million-row raw JSON scan or PHP result buffer.
    $consume=function(string $sql,array $args,string $family)use(&$groups,&$totals,&$families,$names,$devices,$add):void{
        $pdo=db();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,false);$s=null;
        try{
            $s=$pdo->prepare($sql);$s->execute($args);
            while($r=$s->fetch()){
                $n=(int)$r['n'];$outcome=$r['outcome'];$family=$r['reason_family']??$family;$key=$family.':'.$r['group_key'];
                $totals['records']+=$n;$families[$outcome]['records']+=$n;
                if($r['group_key']!==null)$groups->add($key,['outcome'=>$outcome],0);
                $source=$r['srcip'];$profile=$r['profile'];$policy=(int)$r['policyid'];$local=$r['subtype']==='local';
                $add('sources',$source,['label'=>$source?:'Kaynak IP alanı yok','name'=>$devices[$source]??'','filter'=>$source!==''?['source'=>$source]:['source_missing'=>'1']],$n);
                $policyScope=$local?'local':'forward';$policyKey=$policyScope.':'.$policy;
                $add('policies',$policyKey,['label'=>$policy>=0?'Policy '.$policy:'Policy alanı yok','name'=>$local?'Local trafik':implode(' / ',array_keys($names[$policy]??[])),'policy_scope'=>$policyScope,'filter'=>['policy'=>(string)$policy,'policy_scope'=>$policyScope]],$n);
                $add('profiles',$profile,['label'=>$profile!==''?$profile:'Profil alanı yok','missing'=>$profile==='','filter'=>$profile!==''?['profile'=>$profile]:['profile_missing'=>'1']],$n);
                $reasonKey=$family.':'.hash('sha256',$r['subtype'].'|'.$r['reason_json']);$reason=json_decode($r['reason_json'],true,512,JSON_THROW_ON_ERROR);
                $parts=array_filter([$reason['virus']??'',$reason['attack']??'',$reason['catdesc']??'',$reason['app']??'',$reason['certdesc']??'',$reason['reason']??'',$reason['error']??'',$reason['msg']??''],fn($v)=>$v!=='');
                $label=implode(' · ',array_unique($parts));
                if($label==='')$label=($reason['attackid']??'')!==''?'Saldırı imzası #'.$reason['attackid']:(($reason['cat']??'')!==''?'Kategori #'.$reason['cat']:'Ayrıntılı gerekçe logda belirtilmemiş');
                $add('reasons',$reasonKey,['label'=>$label,'module'=>$r['subtype'],'outcome'=>$outcome,'reason_code'=>$reason['code']??'','filter'=>['block_reason'=>$reasonKey]],$n);
            }
        }finally{if($s)$s->closeCursor();$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY,true);}
    };
    require_once __DIR__.'/archive-query.php';
    $watermark=archive_watermark();
    if($watermark!==null){
        $filters=['outcome'=>$outcomes[$kind]??'all_blocks'];
        [$sql,$args]=archive_summary_query($filters,$from,$to,$watermark,true);$consume($sql,$args,'');
        foreach(archive_group_counts($filters,$from,$to,$watermark) as $r){$totals['groups']+=(int)$r['n'];$families[$r['outcome']]['groups']+=(int)$r['n'];}
    }else{
    if(in_array($kind,['all','local','policy'],true)){
        $restrict=' WHERE '.fg_identity_scope('g').($outcomes[$kind]?" AND g.outcome='".$outcomes[$kind]."'":'');
        $consume("SELECT HEX(g.group_key) group_key,g.srcip,g.policyid,m.profile,g.subtype,g.outcome,JSON_EXTRACT(g.identity_json,'$.reason') reason_json,m.n FROM (SELECT group_key,profile,COUNT(*) n FROM traffic_event_groups FORCE INDEX(summary_cover) WHERE event_at>=? AND event_at<? GROUP BY group_key,BINARY profile) m JOIN traffic_groups g ON g.group_key=m.group_key $restrict",[$from,$to],'t');
    }
    if(in_array($kind,['all','security'],true)){
        $consume("SELECT HEX(g.group_key) group_key,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,JSON_EXTRACT(g.identity_json,'$.reason') reason_json,COUNT(*) n FROM security_event_groups g JOIN events e ON e.id=g.event_id WHERE ".fg_event_scope('e')." AND e.event_at>=? AND e.event_at<? AND e.outcome='security_block' GROUP BY g.group_key,e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome,reason_json",[$from,$to],'s');
        $avReason=antivirus_reason_sql('e');
        $consume("SELECT HEX(g.group_key) group_key,e.srcip,e.policyid,e.profile,e.subtype,e.outcome,$avReason reason_json,COUNT(*) n FROM av_event_groups g JOIN events e ON e.id=g.event_id WHERE ".fg_event_scope('e')." AND e.event_at>=? AND e.event_at<? AND e.outcome='security_block' GROUP BY g.group_key,e.srcip,e.policyid,BINARY e.profile,e.subtype,e.outcome,reason_json",[$from,$to],'a');
    }
    }
    $groups->finish(0,function(array $row)use(&$totals,&$families):void{$totals['groups']++;$families[$row['outcome']]['groups']++;});
    foreach($rankings as &$rows){
        $rows=$rows->finish()['rows'];
        foreach($rows as &$r){$r['percent']=$totals['records']?round(100*$r['records']/$totals['records'],2):0;$r['filter']=['outcome'=>$outcomes[$kind]??'all_blocks']+$r['filter'];}unset($r);
    }unset($rows);
    return ['scope'=>['from_utc'=>$from,'to_utc'=>$to,'kind'=>$kind],'totals'=>$totals,'families'=>array_values($families),'rankings'=>$rankings,'counting'=>'original_block_records','generated_at'=>gmdate('c')];
}
