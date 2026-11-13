#!/usr/bin/php
<?php
declare(strict_types=1);
/** Run as a local database administrator while fls-archive-indexer is stopped.
 * The raw collector and importer remain active. No original rows are changed.
 * Existing v2 summaries can be upgraded without replay only when they represent
 * exactly one device/VDOM. Ambiguous historical summaries are refused.
 */
if(PHP_SAPI!=='cli'||!in_array('--apply',$argv,true))exit("Usage: php bin/migrate-device-scope.php --apply\n");
$database=getenv('FLS_MIGRATION_DATABASE')?:'fls';
if(!preg_match('/^(fls|fls_qa_[a-z0-9_]+)$/D',$database))throw new RuntimeException('Unexpected migration database');
function db(): PDO {global $database;static $p;return $p??=new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname='.$database.';charset=utf8mb4','root','',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);}
function query(string $q,array $a=[]): array {$s=db()->prepare($q);$s->execute($a);return $s->fetchAll();}
function execute(string $q,array $a=[]): void {$s=db()->prepare($q);$s->execute($a);}
require __DIR__.'/../app/device-rollup.php';
function migration_identities(): array {
    // Binary MIN/MAX scans only the covering identity index. Case-distinct VDOMs
    // must not be collapsed by the original table's case-insensitive collation.
    $r=query('SELECT MIN(BINARY devid) serial_min,MAX(BINARY devid) serial_max,MIN(BINARY vd) vdom_min,MAX(BINARY vd) vdom_max FROM events FORCE INDEX(session_lookup)')[0];
    if($r['serial_min']===null)return [];
    if($r['serial_min']!==$r['serial_max']||$r['vdom_min']!==$r['vdom_max'])throw new RuntimeException('Mixed v2 history requires rebuilding derived summaries per device; no data assigned');
    return [['devid'=>$r['serial_min'],'vd'=>$r['vdom_min']]];
}

db()->exec("SET time_zone='+00:00',max_statement_time=300");
$version=(int)query('SELECT version FROM archive_index_state WHERE id=1')[0]['version'];
if($version===3){echo "Device scope already migrated.\n";exit;}
if($version!==2)throw new RuntimeException('Unexpected archive version');
// Covering identity verification; original payloads are never read or replayed.
$verifiedHigh=(int)(query('SELECT id FROM events ORDER BY id DESC LIMIT 1')[0]['id']??0);
$identities=migration_identities();
if(count($identities)>1)throw new RuntimeException('Mixed v2 history requires rebuilding derived summaries per device; no changes applied');
foreach(explode(';',file_get_contents(__DIR__.'/../migrations/019-device-scope.sql')) as $statement)if(trim($statement)!=='')db()->exec($statement);
db()->beginTransaction();
try{
    // Lock only the derived cursor. All source events and original hourly counts
    // are read from one consistent InnoDB snapshot while ingestion continues.
    $state=query('SELECT * FROM archive_index_state WHERE id=1 FOR UPDATE')[0];
    if((int)$state['version']!==2)throw new RuntimeException('Archive version changed');
    // Original events are append-only. The covering verification already
    // includes every row <= verifiedHigh; only new IDs need a second check.
    $newIdentities=query('SELECT DISTINCT BINARY devid devid,BINARY vd vd FROM events FORCE INDEX(PRIMARY) WHERE id>?',[$verifiedHigh]);
    foreach($newIdentities as $newIdentity){if(!$identities)$identities=[$newIdentity];elseif($newIdentity!==$identities[0])throw new RuntimeException('Mixed v2 history arrived during preparation');}
    $last=(int)(query('SELECT id FROM events ORDER BY id DESC LIMIT 1')[0]['id']??0);
    if($last-(int)$state['event_id']>10000)throw new RuntimeException('Drain the derived index before migrating');
    if(query('SELECT 1 FROM device_hourly_counts LIMIT 1'))throw new RuntimeException('Unexpected pre-existing device summaries');
    if($identities){
        $identity=$identities[0];
        $buckets=[];
        foreach(query('SELECT hour_at,type,subtype,outcome,rating_error,policyid,profile,reason_code,records FROM hourly_counts') as $r){$r=$identity+$r;$buckets[bin2hex(device_metric_key($r))]=$r;}
        // Remove the bounded original tail from the imported hourly snapshot.
        // The v3 worker adds it once as it advances this exact same watermark.
        foreach(query("SELECT devid,vd,CAST(DATE_FORMAT(event_at,'%Y-%m-%d %H:00:00') AS DATETIME) hour_at,type,subtype,outcome,rating_error,policyid,profile,reason_code,COUNT(*) records FROM events FORCE INDEX(PRIMARY) WHERE id>? GROUP BY devid,vd,hour_at,type,subtype,outcome,rating_error,policyid,BINARY profile,reason_code",[$state['event_id']]) as $r){$key=bin2hex(device_metric_key($r));if(!isset($buckets[$key]))throw new RuntimeException('Hourly source mismatch');$buckets[$key]['records']-=(int)$r['records'];if($buckets[$key]['records']<0)throw new RuntimeException('Negative checkpoint bucket');}
        device_metric_write(array_values(array_filter($buckets,fn($r)=>(int)$r['records']>0)));
        foreach(query('SELECT * FROM archive_dimensions') as $r){$r=array_replace($r,$identity);execute('UPDATE archive_dimensions SET devid=?,vd=?,fingerprint=? WHERE id=?',[$r['devid'],$r['vd'],device_dimension_key($r),$r['id']]);}
        // All original observations share this verified identity. Later worker
        // observations use timestamps so late arrivals cannot regress names.
        foreach([['device_policies','policies','policyid,poluuid,name,observed_at',6],['device_sources','devices','ip,name,observed_at',5]] as [$target,$source,$columns,$n]){
            // INSERT SELECT would use a locking/current read of the live source
            // and can fail with error 1020 during concurrent importer updates.
            // Fetch the consistent snapshot first, then insert explicit values.
            foreach(array_chunk(query('SELECT '.$columns.' FROM '.$source),300) as $chunk){$args=[];foreach($chunk as $r)array_push($args,$identity['devid'],$identity['vd'],...array_values($r));execute('INSERT INTO '.$target.'(devid,vd,'.$columns.') VALUES '.implode(',',array_fill(0,count($chunk),'('.implode(',',array_fill(0,$n,'?')).')')),$args);}
        }
    }
    execute('UPDATE archive_index_state SET version=3,updated_at=UTC_TIMESTAMP(6) WHERE id=1');
    db()->commit();
    echo json_encode(['version'=>3,'checkpoint'=>(int)$state['event_id'],'identities'=>$identities,'original_rows_changed'=>0],JSON_THROW_ON_ERROR)."\n";
}catch(Throwable $e){if(db()->inTransaction())db()->rollBack();throw $e;}
