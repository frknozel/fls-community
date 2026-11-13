<?php
declare(strict_types=1);
require_once __DIR__.'/telemetry.php';

function backlog_alert_time(mixed $value): ?DateTimeImmutable {
    if(!is_string($value)||!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/D',$value))return null;
    try{return (new DateTimeImmutable($value))->setTimezone(new DateTimeZone('UTC'));}catch(Throwable){return null;}
}
/** Current alert is independent of the dashboard's log date filters. */
function summary_backlog_alert(?array $sample=null,?DateTimeImmutable $now=null,string $key='archive_index_alert'): array {
    $now??=new DateTimeImmutable('now',new DateTimeZone('UTC'));
    $result=['status'=>'unavailable','active'=>null,'fresh'=>false,'rule'=>null,'checked_at'=>null,
        'pending_records'=>null,'last_pending_records'=>null,'started_at'=>null,'activated_at'=>null,
        'last_confirmed_at'=>null,'peak_pending'=>null,'observed_seconds'=>null,'window'=>null];
    $sample??=telemetry_latest();$raw=$sample[$key]??null;
    if(!is_array($raw)||($raw['schema']??null)!==1||!is_bool($raw['active']??null)||!in_array($raw['status']??null,['clear','watching','active','unknown'],true))return $result;
    $rule=$raw['rule']??null;
    if(!is_array($rule))return $result;
    foreach(['minimum_pending','minimum_seconds','maximum_gap_seconds','stale_after_seconds'] as $key)if(!is_int($rule[$key]??null)||$rule[$key]<1||$rule[$key]>1000000000)return $result;
    $at=backlog_alert_time($raw['at']??null);$sampleAt=backlog_alert_time($sample['at']??null);
    if(!$at||!$sampleAt||$at!=$sampleAt)return $result;
    $age=(float)$now->format('U.u')-(float)$at->format('U.u');
    $fresh=$age>=-5&&$age<=$rule['stale_after_seconds']&&$raw['status']!=='unknown';
    $result['rule']=$rule;$result['checked_at']=$raw['at'];$result['fresh']=$fresh;
    $result['status']=$fresh?$raw['status']:'unknown';$result['active']=$raw['active']?true:($fresh?false:null);
    $pending=$raw['pending_records']??null;
    if(($raw['status']==='active')!==$raw['active']&&$raw['status']!=='unknown'||$raw['active']&&$fresh&&$pending===0)return ['status'=>'unknown','active'=>$raw['active']?true:null,'fresh'=>false]+$result;
    if($fresh&&(!is_int($pending)||$pending<0))return ['status'=>'unknown','active'=>$raw['active']?true:null,'fresh'=>false]+$result;
    $result['pending_records']=$fresh?$pending:null;
    if(!$raw['active'])return $result;
    $start=backlog_alert_time($raw['started_at']??null);$activated=backlog_alert_time($raw['activated_at']??null);$confirmed=backlog_alert_time($raw['last_confirmed_at']??null);
    $peak=$raw['peak_pending']??null;$last=$raw['last_pending_records']??null;
    if(!$start||!$activated||!$confirmed||$start>$activated||$activated>$confirmed||$confirmed>$at||$activated->getTimestamp()-$start->getTimestamp()<$rule['minimum_seconds']||!is_int($peak)||$peak<$rule['minimum_pending']||!is_int($last)||$last<1||$last>$peak)return ['status'=>'unknown','fresh'=>false,'pending_records'=>null]+$result;
    foreach(['started_at','activated_at','last_confirmed_at','peak_pending','last_pending_records'] as $key)$result[$key]=$raw[$key];
    $result['observed_seconds']=max(0,$confirmed->getTimestamp()-$start->getTimestamp());
    $from=max($start->modify('-5 minutes'),$now->modify('-90 days'));$to=$at->modify('+30 seconds');
    if($from<$to)$result['window']=['from_utc'=>$from->format('Y-m-d\TH:i:s.u\Z'),'to_utc'=>$to->format('Y-m-d\TH:i:s.u\Z')];
    return $result;
}

/** Search queue uses its own persisted state and fixed initial rule. */
function mail_search_backlog_alert(?array $sample=null,?DateTimeImmutable $now=null): array {
    return summary_backlog_alert($sample,$now,'mail_search_index_alert');
}
