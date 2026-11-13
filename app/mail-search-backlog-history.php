<?php
declare(strict_types=1);
require_once __DIR__.'/backlog-alert.php';
function mail_search_backlog_history_iso(?string $value): ?string {return $value?(new DateTimeImmutable($value,new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z'):null;}
function mail_search_backlog_history_report(): array {
    [$from,$to]=scope();$requested=$_GET['mail_backlog_history_page']??'1';
    if(!is_string($requested)||!preg_match('/^[1-9][0-9]{0,5}$/D',$requested)||($page=(int)$requested)>100000)throw new InvalidArgumentException('Geçerli bir uyarı geçmişi sayfası seçin.');
    $result=['scope'=>['from_utc'=>$from,'to_utc'=>$to],'rows'=>[],'total'=>0,'page'=>1,'page_size'=>20,'counts'=>[],
        'status'=>'unavailable','fresh'=>false,'coverage_from_at'=>null,'last_sample_at'=>null,'checked_at'=>null,'graph_retention_days'=>90];
    try{
        $state=query('SELECT * FROM mail_search_backlog_history_state WHERE id=1')[0]??null;
        if(!$state||(int)$state['version']!==1)return $result;
        $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));$latest=telemetry_latest();$source=backlog_alert_time($latest['at']??null);
        $age=$state['updated_at']?$now->getTimestamp()-(new DateTimeImmutable($state['updated_at'],new DateTimeZone('UTC')))->getTimestamp():PHP_INT_MAX;
        $lag=$source&&$state['last_sample_at']?$source->getTimestamp()-(new DateTimeImmutable($state['last_sample_at'],new DateTimeZone('UTC')))->getTimestamp():PHP_INT_MAX;
        $fresh=$age>=-5&&$age<=120&&$source&&abs($now->getTimestamp()-$source->getTimestamp())<=120;
        $result['fresh']=$fresh&&(bool)$state['ready']&&$lag<=95;
        $result['status']=!$fresh?'stale':($result['fresh']?'ready':'processing');
        foreach(['coverage_from_at','last_sample_at'] as $key)$result[$key]=mail_search_backlog_history_iso($state[$key]);$result['checked_at']=mail_search_backlog_history_iso($state['updated_at']);
        $where='triggered_at < ? AND (resolved_at IS NULL OR resolved_at >= ?)';$params=[$to,$from];
        $counts=query('SELECT status,COUNT(*) n FROM mail_search_backlog_incidents WHERE '.$where.' GROUP BY status',$params);
        foreach($counts as $row)$result['counts'][$row['status']]=(int)$row['n'];$total=array_sum($result['counts']);$page=min($page,max(1,(int)ceil($total/20)));
        $rows=query('SELECT * FROM mail_search_backlog_incidents WHERE '.$where.' ORDER BY triggered_at DESC,id DESC LIMIT 20 OFFSET '.(($page-1)*20),$params);
        foreach($rows as &$row){
            foreach(['id','minimum_pending','minimum_seconds','peak_pending','last_pending'] as $key)$row[$key]=(int)$row[$key];
            $row['settings_revision']=$row['settings_revision']!==null?(int)$row['settings_revision']:null;$row['had_measurement_gap']=(bool)$row['had_measurement_gap'];
            $start=new DateTimeImmutable($row['started_at'],new DateTimeZone('UTC'));$end=new DateTimeImmutable($row['resolved_at']??$row['last_sample_at'],new DateTimeZone('UTC'));
            $row['observed_seconds']=max(0,$end->getTimestamp()-$start->getTimestamp());$windowFrom=max($start->modify('-5 minutes'),$now->modify('-90 days'));$windowTo=$end->modify('+30 seconds');
            $row['window']=$windowFrom<$windowTo?['from_utc'=>$windowFrom->format('Y-m-d\TH:i:s.u\Z'),'to_utc'=>$windowTo->format('Y-m-d\TH:i:s.u\Z')]:null;
            $row['graph_truncated']=$windowFrom>$start->modify('-5 minutes');
            foreach(['started_at','triggered_at','last_confirmed_at','last_sample_at','resolved_at','drained_at'] as $key)$row[$key]=mail_search_backlog_history_iso($row[$key]);
            unset($row['incident_key']);
        }unset($row);$result['rows']=$rows;$result['total']=$total;$result['page']=$page;return $result;
    }catch(PDOException $e){error_log('FLS backlog history read failed: SQLSTATE '.$e->getCode());return ['status'=>'unavailable','fresh'=>false]+$result;}
}
