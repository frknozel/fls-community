<?php
declare(strict_types=1);
require_once __DIR__.'/backlog-alert.php';

function msbhi_sql_time(string $value): string {return (new DateTimeImmutable($value,new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');}
function msbhi_gap(array &$state): void {
    $state['gap_count']=(int)$state['gap_count']+1;
    if($state['open_key'])execute('UPDATE mail_search_backlog_incidents SET had_measurement_gap=1 WHERE incident_key=?',[$state['open_key']]);
}
function msbhi_close(array &$state,string $status,string $at): void {
    execute("UPDATE mail_search_backlog_incidents SET status=?,resolved_at=?,drained_at=?,last_sample_at=? WHERE incident_key=? AND status='active'",[$status,$at,$status==='drained'?$at:null,$at,$state['open_key']]);
    if($status==='drained')execute('UPDATE mail_search_backlog_incidents SET last_pending=0,last_confirmed_at=? WHERE incident_key=?',[$at,$state['open_key']]);
    $state['open_key']=null;
}
/** A committed warning state is evidence. Never recreate warnings from counts. */
function msbhi_sample(array $sample,array &$state): void {
    $at=backlog_alert_time($sample['at']??null);if(!$at){if($state['coverage_from_at'])msbhi_gap($state);return;}
    if($at->getTimestamp()>time()+5){if($state['coverage_from_at'])msbhi_gap($state);return;}
    $sqlAt=$at->format('Y-m-d H:i:s.u');
    if($state['last_sample_at']!==null&&$sqlAt<=$state['last_sample_at'])return;
    $gap=$state['last_sample_at']!==null&&$at->getTimestamp()-(new DateTimeImmutable($state['last_sample_at'],new DateTimeZone('UTC')))->getTimestamp()>95;
    if($gap&&$state['coverage_from_at'])msbhi_gap($state);
    $state['last_sample_at']=$sqlAt;$raw=$sample['mail_search_index_alert']??null;$info=mail_search_backlog_alert($sample,$at);
    if($info['status']==='unavailable'){
        if($state['coverage_from_at'])msbhi_gap($state);
        return;
    }
    $state['coverage_from_at']??=$sqlAt;
    if(!$info['fresh'])msbhi_gap($state);
    if($info['active']===true&&$info['started_at']&&$info['activated_at']&&$info['last_confirmed_at']){
        $start=msbhi_sql_time($info['started_at']);$trigger=msbhi_sql_time($info['activated_at']);$confirmed=msbhi_sql_time($info['last_confirmed_at']);
        $rule=$info['rule'];$key=hash('sha256',$start.'|'.$trigger.'|'.$rule['minimum_pending'].'|'.$rule['minimum_seconds']);
        if($state['open_key']&&$state['open_key']!==$key){
            $old=query('SELECT minimum_pending,minimum_seconds FROM mail_search_backlog_incidents WHERE incident_key=?',[$state['open_key']])[0]??[];
            $changed=(int)($old['minimum_pending']??0)!==$rule['minimum_pending']||(int)($old['minimum_seconds']??0)!==$rule['minimum_seconds'];
            msbhi_close($state,$changed?'rule_changed':'unconfirmed',$sqlAt);
        }
        $revision=$raw['settings_revision']??null;$revision=is_int($revision)&&$revision>0?$revision:null;
        if($state['open_key']!==$key){
            execute("INSERT IGNORE INTO mail_search_backlog_incidents(incident_key,started_at,triggered_at,minimum_pending,minimum_seconds,settings_revision,peak_pending,last_pending,last_confirmed_at,last_sample_at,status,had_measurement_gap) VALUES(?,?,?,?,?,?,?,?,?,?,'active',?)",[$key,$start,$trigger,$rule['minimum_pending'],$rule['minimum_seconds'],$revision,$info['peak_pending'],$info['last_pending_records'],$confirmed,$sqlAt,(int)(!$info['fresh']||$gap||$start<$state['coverage_from_at'])]);
            $existing=query('SELECT status FROM mail_search_backlog_incidents WHERE incident_key=?',[$key])[0];
            if($existing['status']!=='active')return;
            $state['open_key']=$key;
        }
        execute('UPDATE mail_search_backlog_incidents SET peak_pending=GREATEST(peak_pending,?),last_pending=?,last_confirmed_at=GREATEST(last_confirmed_at,?),last_sample_at=?,had_measurement_gap=GREATEST(had_measurement_gap,?) WHERE incident_key=?',[$info['peak_pending'],$info['last_pending_records'],$confirmed,$sqlAt,(int)!$info['fresh'],$key]);
    }elseif($state['open_key']&&$info['fresh']){
        if($info['pending_records']===0)msbhi_close($state,'drained',$sqlAt);
        else{
            $old=query('SELECT minimum_pending,minimum_seconds FROM mail_search_backlog_incidents WHERE incident_key=?',[$state['open_key']])[0]??[];
            $changed=(int)($old['minimum_pending']??0)!==($info['rule']['minimum_pending']??0)||(int)($old['minimum_seconds']??0)!==($info['rule']['minimum_seconds']??0);
            msbhi_close($state,$changed?'rule_changed':'unconfirmed',$sqlAt);
        }
    }
}
/** Checkpoint and incidents commit together; work and memory are bounded. */
function mail_search_backlog_history_index(string $root=TELEMETRY_ROOT,int $limit=4000,float $budget=8): array {
    $pdo=db();$pdo->beginTransaction();$count=0;$started=microtime(true);$complete=true;
    try{
        $state=query('SELECT * FROM mail_search_backlog_history_state WHERE id=1 FOR UPDATE')[0]??null;
        if(!$state||(int)$state['version']!==1)throw new RuntimeException('History state unavailable');
        $paths=array_values(array_filter(glob($root.'/????-??-??.jsonl')?:[],fn($p)=>preg_match('/^\d{4}-\d{2}-\d{2}\.jsonl$/D',basename($p))));sort($paths);
        if($state['cursor_file']!==''&&!is_file($root.'/'.$state['cursor_file'])){msbhi_gap($state);$state['cursor_file']='';$state['cursor_offset']=0;$state['cursor_inode']=0;}
        foreach($paths as $path){
            $name=basename($path);if($name<$state['cursor_file'])continue;
            $stream=fopen($path,'rb');if(!$stream)throw new RuntimeException('History source unavailable');
            try{
                $stat=fstat($stream);$offset=$name===$state['cursor_file']?(int)$state['cursor_offset']:0;
                if($name===$state['cursor_file']&&((int)$state['cursor_inode']!==$stat['ino']||$offset>$stat['size'])){msbhi_gap($state);$offset=0;}
                if(fseek($stream,$offset)!==0)throw new RuntimeException('History source seek failed');
                while(($line=fgets($stream,65537))!==false){
                    if(!str_ends_with($line,"\n")){$complete=false;break 2;}
                    $row=json_decode($line,true);
                    if(is_array($row))msbhi_sample($row,$state);elseif($state['coverage_from_at'])msbhi_gap($state);
                    $state['cursor_file']=$name;$state['cursor_offset']=ftell($stream);$state['cursor_inode']=$stat['ino'];$count++;
                    if($count>=$limit||microtime(true)-$started>=$budget){$complete=false;break 2;}
                }
                $state['cursor_file']=$name;$state['cursor_offset']=ftell($stream);$state['cursor_inode']=$stat['ino'];
            }finally{fclose($stream);}
        }
        execute('UPDATE mail_search_backlog_history_state SET cursor_file=?,cursor_offset=?,cursor_inode=?,last_sample_at=?,coverage_from_at=?,open_key=?,gap_count=?,ready=?,updated_at=UTC_TIMESTAMP(6) WHERE id=1',[$state['cursor_file'],$state['cursor_offset'],$state['cursor_inode'],$state['last_sample_at'],$state['coverage_from_at'],$state['open_key'],$state['gap_count'],(int)$complete]);
        $pdo->commit();return ['rows'=>$count,'ready'=>$complete];
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
