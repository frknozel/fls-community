<?php
declare(strict_types=1);

/** Shared, pure backup schedule and freshness rules. */
function operations_time(mixed $value): ?DateTimeImmutable {
    if(!is_string($value)||!preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$/D',$value))return null;
    try{$time=new DateTimeImmutable($value,new DateTimeZone('UTC'));$errors=DateTimeImmutable::getLastErrors();return $errors&&($errors['warning_count']||$errors['error_count'])?null:$time->setTimezone(new DateTimeZone('UTC'));}catch(Throwable){return null;}
}
function operations_last_due(DateTimeImmutable $now,string $clock): DateTimeImmutable {
    $local=$now->setTimezone(new DateTimeZone('Europe/Istanbul'));
    [$hour,$minute]=array_map('intval',explode(':',$clock));$due=$local->setTime($hour,$minute);
    return ($due>$local?$due->modify('-1 day'):$due)->setTimezone(new DateTimeZone('UTC'));
}
function operations_job_state(mixed $row,DateTimeImmutable $due,DateTimeImmutable $now,int $maximumSeconds=1200): string {
    if($row===null)return 'never';if(!is_array($row)||!$row)return 'unknown';
    if(($row['status']??'')==='failed')return 'failed';
    if(($row['status']??'')==='running'){
        $started=operations_time($row['started_at_utc']??null);
        return !$started||$started>$now->modify('+5 seconds')?'unknown':($now->getTimestamp()-$started->getTimestamp()>$maximumSeconds?'stuck':'running');
    }
    if(($row['status']??'')!=='succeeded')return 'unknown';
    // A manual afternoon run cannot satisfy the later scheduled 23:00 snapshot.
    $captured=operations_time($row['snapshot_at_utc']??$row['started_at_utc']??null);
    $completed=operations_time($row['completed_at_utc']??null);
    if(!$captured||!$completed||$captured>$completed||$completed>$now->modify('+5 seconds'))return 'unknown';
    if($captured<$due&&$now>=$due->modify('+30 minutes'))return 'overdue';
    return $captured<$due?'waiting':'current';
}
