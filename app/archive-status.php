<?php
declare(strict_types=1);

/** Called inside the health route's read-only snapshot; no archive scans or writes. */
function archive_index_status(): array {
    $result=['status'=>'unavailable','updated_at'=>null,'checked_at'=>gmdate('c'),
        'pending_records'=>null,'caught_up'=>null,'ready'=>false,'fresh'=>false,
        'heartbeat_age_seconds'=>null,'stale_after_seconds'=>60];
    try{
        $state=query('SELECT version,event_id,ready,updated_at,UTC_TIMESTAMP(6) checked_at FROM archive_index_state WHERE id=1')[0]??null;
        if(!$state)return $result;
        $zone=new DateTimeZone('UTC');
        $updated=new DateTimeImmutable($state['updated_at'],$zone);$now=new DateTimeImmutable($state['checked_at'],$zone);
        $age=(float)$now->format('U.u')-(float)$updated->format('U.u');
        $result['updated_at']=$updated->format('Y-m-d\TH:i:s.u\Z');
        $result['checked_at']=$now->format('Y-m-d\TH:i:s.u\Z');
        $result['heartbeat_age_seconds']=max(0,(int)floor($age));
        if((int)$state['version']!==3)return ['status'=>'incompatible']+$result;
        $last=(int)(query('SELECT id FROM events ORDER BY id DESC LIMIT 1')[0]['id']??0);
        $cursor=(int)$state['event_id'];
        if($cursor<0 || $cursor>$last || $age < -5 || !in_array((int)$state['ready'],[0,1],true))return ['status'=>'unknown']+$result;
        if($cursor && !query('SELECT id FROM events WHERE id=?',[$cursor]))return ['status'=>'unknown']+$result;
        // IDs can have gaps: count actual records. For a large backlog, read only
        // the small covering index instead of fetching original event payloads.
        $index=$last-$cursor>10000?'metric_cover':'PRIMARY';
        $result['pending_records']=(int)query("SELECT COUNT(*) n FROM events FORCE INDEX($index) WHERE id>?",[$cursor])[0]['n'];
        $result['ready']=(int)$state['ready']===1;
        $result['fresh']=$age <= $result['stale_after_seconds'];
        if(!$result['fresh'])return ['status'=>'stale']+$result;
        $result['caught_up']=$result['ready'] && $result['pending_records']===0;
        return ['status'=>!$result['ready']?'backfilling':($result['caught_up']?'caught_up':'processing')]+$result;
    }catch(PDOException $e){
        if($e->getCode()!=='42S02')error_log('FLS archive index status failed: SQLSTATE '.$e->getCode());
        return ['status'=>$e->getCode()==='42S02'?'unavailable':'unknown']+$result;
    }
}

/** Server-wide live mail-search progress, inside the health read-only snapshot. */
function mail_search_index_status(): array {
    $result=['status'=>'unavailable','updated_at'=>null,'checked_at'=>gmdate('c'),
        'pending_records'=>null,'caught_up'=>null,'ready'=>false,'fresh'=>false,
        'heartbeat_age_seconds'=>null,'stale_after_seconds'=>60];
    try{
        $state=query('SELECT version,event_id,ready,updated_at,UTC_TIMESTAMP(6) checked_at FROM mail_search_state WHERE id=1')[0]??null;
        if(!$state)return $result;
        if((int)$state['version']!==1)return ['status'=>'incompatible']+$result;
        if(!$state['updated_at'])return $result;
        if(str_starts_with($state['updated_at'],'0000-'))return ['status'=>'unknown']+$result;
        $zone=new DateTimeZone('UTC');
        $updated=new DateTimeImmutable($state['updated_at'],$zone);$now=new DateTimeImmutable($state['checked_at'],$zone);
        $age=(float)$now->format('U.u')-(float)$updated->format('U.u');
        $result['updated_at']=$updated->format('Y-m-d\TH:i:s.u\Z');
        $result['checked_at']=$now->format('Y-m-d\TH:i:s.u\Z');
        $result['heartbeat_age_seconds']=max(0,(int)floor($age));
        $last=(int)(query('SELECT id FROM events ORDER BY id DESC LIMIT 1')[0]['id']??0);
        $cursor=(int)$state['event_id'];
        if($cursor<0||$cursor>$last||$age < -5||!in_array((int)$state['ready'],[0,1],true))return ['status'=>'unknown']+$result;
        if($cursor&&!query('SELECT id FROM events WHERE id=?',[$cursor]))return ['status'=>'unknown']+$result;
        $result['ready']=(int)$state['ready']===1;$result['fresh']=$age<=$result['stale_after_seconds'];
        // Count real original rows (all types), including gaps in auto-increment IDs.
        // Large backlogs use a narrow covering index; the per-query budget also
        // keeps an unavailable monitor from blocking the other health cards.
        $index=$last-$cursor>10000?'metric_cover':'PRIMARY';
        $result['pending_records']=(int)query("SET STATEMENT max_statement_time=2 FOR SELECT COUNT(*) n FROM events FORCE INDEX($index) WHERE id>?",[$cursor])[0]['n'];
        if(!$result['fresh'])return ['status'=>'stale']+$result;
        $result['caught_up']=$result['ready']&&$result['pending_records']===0;
        return ['status'=>!$result['ready']?'backfilling':($result['caught_up']?'caught_up':'processing')]+$result;
    }catch(PDOException $e){
        if($e->getCode()!=='42S02')error_log('FLS mail search status failed: SQLSTATE '.$e->getCode());
        return ['status'=>$e->getCode()==='42S02'?'unavailable':'unknown']+$result;
    }
}
