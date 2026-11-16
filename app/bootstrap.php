<?php
declare(strict_types=1);
require_once __DIR__.'/recovery-rehearsal.php';
require_once __DIR__.'/fortigate.php';
date_default_timezone_set('Europe/Istanbul');
// Only the private CLI worker can skip HTTP sessions or select its read-only DB credential.
$flsWorker=PHP_SAPI==='cli'&&defined('FLS_CLI_WORKER')&&FLS_CLI_WORKER===true;
if(!$flsWorker){
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
header('Cache-Control: no-store');
session_name('fls_session');
// Cookie policy is locked in the dedicated PHP-FPM pool.
session_start();
csrf_token();
}
function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $credential=PHP_SAPI==='cli'&&defined('FLS_DATABASE_CREDENTIAL')?FLS_DATABASE_CREDENTIAL:'/etc/fls/app.json';
        $c=json_decode(file_get_contents($credential),true,512,JSON_THROW_ON_ERROR);
        $pdo=new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=fls;charset=utf8mb4',$c['user'],$c['password'],[
            PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false
        ]);
        $pdo->exec("SET time_zone='+00:00', max_statement_time=30,tmp_table_size=67108864,max_heap_table_size=67108864");
    }
    return $pdo;
}
function query(string $sql,array $args=[]): array { $s=db()->prepare($sql);$s->execute($args);return $s->fetchAll(); }
function execute(string $sql,array $args=[]): void { $s=db()->prepare($sql);$s->execute($args); }
function h(mixed $v): string { return htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function json_response(mixed $v,int $status=200): never { http_response_code($status);header('Content-Type: application/json; charset=utf-8');echo json_encode($v,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);exit; }
function audit(string $action,string $detail=''): void { execute('INSERT INTO audit_log(at,username,ip,action,detail) VALUES(UTC_TIMESTAMP(),?,?,?,?)',[$_SESSION['username']??'anonymous',$_SERVER['REMOTE_ADDR']??'', $action,mb_substr($detail,0,500)]); }
function csrf_token(): string {
    if(!is_string($_SESSION['csrf']??null)||$_SESSION['csrf']==='')$_SESSION['csrf']=bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_valid(): bool {
    $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??'';
    return is_string($token)&&$token!==''&&hash_equals(csrf_token(),$token);
}
function csrf(): void { if(!csrf_valid()){http_response_code(403);exit('Oturum doğrulaması başarısız. Sayfayı yenileyin.');} }
/** Return to an anonymous session with a usable form token after revocation or expiry. */
function clear_authenticated_session(): void { session_unset();csrf_token(); }
function authenticated(): bool {
    if (!isset($_SESSION['uid'])) return false;
    if (time()-($_SESSION['last_seen']??0)>28800) { clear_authenticated_session();return false; }
    static $current;
    $current??=query('SELECT id,username,display_name,role,enabled,session_version,must_change FROM users WHERE id=?',[$_SESSION['uid']])[0]??[];
    if(!$current || !(int)$current['enabled'] || (int)($_SESSION['session_version']??0)!==(int)$current['session_version']){clear_authenticated_session();return false;}
    $_SESSION['username']=$current['username'];$_SESSION['display_name']=$current['display_name'];$_SESSION['role']=$current['role'];$_SESSION['must_change']=(bool)$current['must_change'];
    $_SESSION['last_seen']=time();return true;
}
function utc(string $input): string {
    if(!preg_match('/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/D',$input))throw new InvalidArgumentException('Tarih geçersiz.');
    try {
        $date=new DateTimeImmutable($input,new DateTimeZone('Europe/Istanbul'));
        $errors=DateTimeImmutable::getLastErrors();
        if($errors&&($errors['warning_count']||$errors['error_count']))throw new InvalidArgumentException('Tarih geçersiz.');
        return $date->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
    }catch(Exception $e){throw new InvalidArgumentException('Tarih geçersiz.');}
}
function scope(): array {
    $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));
    $preset=$_GET['period']??'today';
    if($preset==='fast')require_once __DIR__.'/retention.php';
    $from=match($preset) {
        'fast'=>$now->modify('-'.retention_fast_days().' days'),
        'hour'=>$now->modify('-1 hour'), '24h'=>$now->modify('-24 hours'),
        '7d'=>$now->modify('-7 days'),'all'=>new DateTimeImmutable('2000-01-01',new DateTimeZone('UTC')),
        default=>(new DateTimeImmutable('today'))->setTimezone(new DateTimeZone('UTC'))
    };
    $start=isset($_GET['from']) && $_GET['from']!=='' ? utc($_GET['from']) : $from->format('Y-m-d H:i:s.u');
    $end=isset($_GET['to']) && $_GET['to']!=='' ? utc($_GET['to']) : $now->format('Y-m-d H:i:s.u');
    if ($start>=$end) throw new InvalidArgumentException('Başlangıç, bitişten önce olmalı.');
    return [$start,$end];
}
function antivirus_reason_sql(string $alias): string {
    return "JSON_OBJECT('code','antivirus','virus',COALESCE(JSON_UNQUOTE(JSON_EXTRACT($alias.fields,'$.virus')),''),'virusid',COALESCE(JSON_UNQUOTE(JSON_EXTRACT($alias.fields,'$.virusid')),''))";
}
function block_reason_hash_sql(string $module,string $reason): string { return "SHA2(CONCAT($module,'|',$reason),256)"; }
function block_reason_filter(): ?array {
    $key=$_GET['block_reason']??'';
    if($key==='')return null;
    if(!is_string($key) || !preg_match('/^([sta]):([a-f0-9]{64})$/D',$key,$m))throw new InvalidArgumentException('Engelleme gerekçesi filtresi geçersiz.');
    return [$m[1],$m[2]];
}
function mail_search_field(): string {
 $field=$_GET['q_field']??'';
 if(!is_string($field)||!in_array($field,['','mail','sender','recipient','filename','message_id'],true))throw new InvalidArgumentException('Arama alanı geçersiz.');
 return $field;
}
function mail_search_term(): string {
 $q=$_GET['q']??'';
 if(!is_string($q)||!mb_check_encoding($q,'UTF-8')||mb_strlen(trim($q))>160||preg_match('/[\x00-\x1f\x7f]/u',$q))throw new InvalidArgumentException('Arama metni en fazla 160 karakter olmalı.');
 return trim($q);
}
function mail_search_requested(): bool {return mail_search_field()!==''&&mail_search_term()!=='';}
function conditions(string $alias='e',bool $rollup=false,bool $includeBlockReason=true,bool $includeText=true): array {
    [$from,$to]=scope();$column=$rollup?'hour_at':'event_at';
    $where=["$alias.$column >= ?","$alias.$column < ?",fg_event_scope($alias)];$params=[$from,$to];
    foreach (['policy'=>'policyid','profile'=>'profile','module'=>'subtype','source'=>'srcip','reason'=>'reason_code'] as $q=>$col) {
        if (isset($_GET[$q]) && $_GET[$q]!=='') {
            if ($rollup && $q==='source') throw new InvalidArgumentException('Source rollup is unavailable.');
            if (strlen((string)$_GET[$q])>($q==='profile'?640:512)) throw new InvalidArgumentException('Filtre çok uzun.');
            $where[]="$alias.$col = ?";$params[]=$_GET[$q];
            if($q==='profile'){$where[]="BINARY $alias.profile=BINARY ?";$params[]=$_GET[$q];}
        }
    }
    foreach(['profile_missing'=>'profile','source_missing'=>'srcip'] as $key=>$col)if(($_GET[$key]??'')==='1')$where[]="$alias.$col=''";
    if(($_GET['policy_scope']??'')!==''){
        if(!in_array($_GET['policy_scope'],['local','forward'],true))throw new InvalidArgumentException('Policy kapsamı geçersiz.');
        $where[]="$alias.subtype".($_GET['policy_scope']==='local'?"='local'":"<>'local'");
    }
    if($includeBlockReason && ($reason=block_reason_filter())){
        if($rollup)throw new InvalidArgumentException('Gerekçe filtresi olay kayıtları gerektirir.');
        [$kind,$hash]=$reason;
        $where[]=match($kind){
            's'=>"$alias.id IN (SELECT br.event_id FROM security_event_groups br WHERE ".block_reason_hash_sql("JSON_UNQUOTE(JSON_EXTRACT(br.identity_json,'$.module'))","JSON_EXTRACT(br.identity_json,'$.reason')").'=?)',
            't'=>"$alias.id IN (SELECT bm.event_id FROM traffic_groups br JOIN traffic_event_groups bm ON bm.group_key=br.group_key WHERE ".block_reason_hash_sql('br.subtype',"JSON_EXTRACT(br.identity_json,'$.reason')").'=?)',
            'a'=>"$alias.id IN (SELECT br.event_id FROM av_event_groups br JOIN events ba ON ba.id=br.event_id WHERE ".block_reason_hash_sql('ba.subtype',antivirus_reason_sql('ba')).'=?)'
        };
        $params[]=$hash;
    }
    if(($_GET['target_key']??'')!=='' || ($_GET['source_reason']??'')!==''){
        if($rollup)throw new InvalidArgumentException('Cihaz özeti filtreleri olay kayıtları gerektirir.');
        require_once __DIR__.'/source-summary.php';
        if($hash=source_hash_filter('target_key')){$where[]="$alias.target_fingerprint=UNHEX(?)";$params[]=$hash;}
        if($hash=source_hash_filter('source_reason')){$where[]=block_reason_hash_sql("$alias.subtype",source_reason_sql($alias)).'=?';$params[]=$hash;}
    }
    $out=$_GET['outcome']??'';
    if ($out==='rating_error') $where[]="$alias.rating_error=1";
    elseif($out==='all_blocks')$where[]="$alias.outcome IN ('security_block','policy_deny','local_deny')";
    elseif ($out!=='') {
        if (!in_array($out,['security_block','local_deny','policy_deny','observed','other_deny'],true)) throw new InvalidArgumentException('Sonuç filtresi geçersiz.');
        $where[]="$alias.outcome=?";$params[]=$out;
    }
    $searchField=mail_search_field();$searchTerm=mail_search_term();
    if ($includeText && $searchTerm!=='') {
        if ($rollup) throw new InvalidArgumentException('Search rollup is unavailable.');
        if($searchField!==''){require_once __DIR__.'/mail-search.php';[$ids,$searchArgs]=mail_search_candidates([$from,$to]);$where[]="$alias.id IN ($ids)";array_push($params,...$searchArgs);return [implode(' AND ',$where),$params];}
        $q=$searchTerm;
        $like='%'.str_replace(['!','%','_'],['!!','!%','!_'],$q).'%';
        $cols=['srcip','srcname','dstip','hostname','app','category','profile','fields'];
        $where[]='('.implode(' OR ',array_map(fn($c)=>"$alias.$c LIKE ? ESCAPE '!'",$cols))." OR $alias.id IN (SELECT COALESCE(shared.event_id,n.event_id) FROM event_notes n JOIN events note_event ON note_event.id=n.event_id AND BINARY note_event.devid=BINARY $alias.devid AND BINARY note_event.vd=BINARY $alias.vd LEFT JOIN av_event_groups original ON original.event_id=n.event_id LEFT JOIN av_event_groups shared ON shared.group_key=original.group_key WHERE n.confirmed_recipient LIKE ? ESCAPE '!' OR n.body LIKE ? ESCAPE '!' OR n.confirmation_source LIKE ? ESCAPE '!'))";
        foreach ($cols as $_) $params[]=$like;
        array_push($params,$like,$like,$like);
    }
    return [implode(' AND ',$where),$params];
}
function explain(array $e,array $f): array {
    $reason=$e['reason_code'];$sub=$e['subtype'];$blocked=$e['outcome']==='security_block';
    if ($e['type']==='traffic' && ($f['utmaction']??'')==='block') {
        return ['title'=>'UTM engeli içeren trafik özeti','text'=>'Trafik özeti action='.$e['action'].' ile kaydedilmiş; utmaction=block güvenlik denetiminde bir engel olduğunu bildiriyor. Bu özet, UTM engel sayısına tekrar eklenmez.','tip'=>'Engelleyen modülü ve profili aynı oturumun UTM kayıtlarından belirleyin. Trafik özetindeki profil alanı engelin kaynağını tek başına göstermez.','blocked'=>true,'module'=>$sub];
    }
    [$title,$text,$tip]=match($reason) {
        'rating_error'=>['FortiGuard sınıflandırma hatası', $blocked?'Sorgu hatası sırasında bu kayıt engellenmiş. Bu, hedefin zararlı olarak sınıflandırıldığı anlamına gelmez.':'Sınıflandırma servisi hatası kaydedilmiş; bu kayıt bir güvenlik engeli değildir.','Kategori izni açmadan önce FortiGuard erişimini ve profil hata davranışını kontrol edin.'],
        'category_block'=>['Web kategorisi engeli','Web filtresi, hedefi “'.($e['category']?:'logda belirtilmeyen').'” kategorisi için engellemiş.','Kategori kararı ile bağlantı ihtiyacını birlikte değerlendirin. Bu kayıt tek başına bulaşma kanıtı değildir.'],
        'application_control'=>[$blocked?'Uygulama kontrolü engeli':'Uygulama kontrolü gözlemi',($e['app']?:'Uygulama').' için '.$e['action'].' eylemi kaydedilmiş.','Uygulama etiketi tek başına bağlantıyı başlatan programı doğrulamaz. Ortak profil kullanan policy’leri kontrol edin.'],
        'dns_profile'=>[$blocked?'DNS filtresi engeli':'DNS filtresi gözlemi',$f['msg']??'DNS profili kararı kaydedilmiş.','Hedef, sorgulanan qname alanıdır. dstip DNS çözümleyicisidir; ipaddr yanıt içindeki adreslerdir.'],
        'ips_signature'=>[$blocked?'IPS imzası engeli':'IPS tespiti / gözlemi',($f['attack']??'İmza adı belirtilmemiş').' · İmza ID: '.($f['attackid']??'belirtilmemiş').' · Eylem: '.$e['action'], $blocked?'Saldırı imzası eşleşmesi, saldırının başarılı olduğunu tek başına kanıtlamaz. Hedef sistemi ve aynı oturumdaki kayıtları inceleyin.':'detected ve pass_session engel değildir. clear_session oturumun kaldırıldığını/kapatıldığını bildirir; bu görünümde engel sayılmaz.'],
        'antivirus'=>['Antivirüs imza eşleşmesi',($f['virus']??'Antivirüs imzası').' — '.($f['filename']??'Dosya adı belirtilmemiş').'.','Tekrar eden kayıtlar aynı ekin yeniden indirilmesi olabilir. Message-ID ve analyticscksum alanlarıyla karşılaştırın.'],
        'certificate_blocklist'=>['Sertifika engel listesi eşleşmesi',$f['certdesc']??'Sertifika FortiGuard engel listesi ile eşleşmiş.','Bu eşleşme cihazda belirli bir yazılım kurulu olduğunu kanıtlamaz. Kaynak süreci ve sertifika karmasını inceleyin.'],
        'ssl_inspection'=>['TLS / sertifika incelemesi',$f['msg']??$f['eventsubtype']??'TLS denetim kaydı.','Web filtresindeki izin kaydı, sonraki SSL denetiminin de izin verdiği anlamına gelmez.'],
        'local_deny'=>['FortiGate’e yönelen trafik reddi','FortiGate’in kendisine gelen trafik için local deny kaydı.','Bunu istemcilerin internet erişimindeki güvenlik profili engellerinden ayrı değerlendirin.'],
        'policy_deny'=>['Firewall policy reddi','İletilen trafik firewall policy aşamasında reddedilmiş.','Policy 0, örtük reddi gösterebilir. Bu satır güvenlik profili engeli değildir.'],
        default=>['Trafik / sistem gözlemi',$f['msg']??('Cihaz eylemi: '.($e['action']?:'belirtilmemiş')), 'Tek bir modülün pass veya close kaydı oturumun tüm denetimlerden geçtiğini kanıtlamaz.']
    };
    return ['title'=>$title,'text'=>$text,'tip'=>$tip,'blocked'=>$blocked,'module'=>$sub];
}
/** Feature decisions are captured once per authenticated API request. */
function event_feature_allowed(string $feature): bool {
    if(isset($GLOBALS['FLS_EVENT_FEATURES'])&&array_key_exists($feature,$GLOBALS['FLS_EVENT_FEATURES']))return $GLOBALS['FLS_EVENT_FEATURES'][$feature]===true;
    require_once __DIR__.'/license.php';return license_feature_allowed($feature);
}
function decorate(array $row): array {
    $analysis=event_feature_allowed('analysis');
    $f=isset($row['fields'])?json_decode($row['fields'],true):[];
    if(isset($row['target_identity_json'])){$target=json_decode($row['target_identity_json'],true,512,JSON_THROW_ON_ERROR);$row['target']=$target+['key'=>strtolower($row['target_key']),'label'=>$target['value']!==''?$target['value']:($target['kind']==='dns_missing'?'Sorgu adı logda yok':'Hedef alanı logda yok')];unset($row['target_identity_json'],$row['target_key']);}
    if(isset($row['reason_identity_json'])){
        if($analysis&&in_array($row['outcome'],['security_block','policy_deny','local_deny'],true))$row['block_explanation']=reason_descriptor('r:'.hash('sha256',$row['subtype'].'|'.$row['reason_identity_json']),$row['subtype'],$row['reason_identity_json']);
        unset($row['reason_identity_json']);
    }
    $row['explanation']=$analysis?explain($row,$f??[]):['title'=>'Cihaz kaydı','text'=>$f['msg']??('Cihaz eylemi: '.($row['action']?:'belirtilmemiş')),'tip'=>'Gelişmiş analiz için lisans doğrulaması gerekiyor. Özgün kayıt ve ayrıştırılan alanlar erişilebilir.','blocked'=>in_array($row['outcome'],['security_block','policy_deny','local_deny'],true),'module'=>$row['subtype']];
    $row['utm_action']=$f['utmaction']??'';
    $row['confirmed_recipients']=json_decode($row['confirmed_recipients_json']??'[]',true)??[];
    unset($row['confirmed_recipients_json']);
    if ($row['subtype']==='virus') {
        $hashField='';
        foreach(['analyticscksum','filehash','checksum'] as $key) if(($f[$key]??'')!=='') { $hashField=$key;break; }
        $row['mail']=[
            'sender'=>$f['from']??'', 'recipient'=>$f['to']??'',
            'filename'=>$f['filename']??'', 'message_id'=>$f['messageid']??'',
            'attachment_hash'=>$hashField!==''?$f[$hashField]:'', 'hash_field'=>$hashField,
        ];
        if($analysis)$row['av_group']=['key'=>$row['av_group_key']??null,'key_complete'=>(bool)($row['group_key_complete']??false),'total_records'=>(int)($row['av_group_total']??1)];
    }
    if ($analysis && !empty($row['security_group_key'])) {
        $row['security_group']=['key'=>$row['security_group_key'],'key_complete'=>(bool)$row['security_key_complete'],'total_records'=>(int)$row['security_group_total'],'identity'=>json_decode($row['security_identity_json'],true)];
    }
    unset($row['security_identity_json']);
    if($analysis && !empty($row['traffic_group_key'])) {
        $stats=traffic_group_stats($row['traffic_group_key']);
        $row['traffic_group']=['key'=>$row['traffic_group_key'],'key_complete'=>(bool)$row['traffic_key_complete'],'total_records'=>$stats['total_records'],'identity'=>json_decode($row['traffic_identity_json'],true)];
        $row['traffic_group_total']=$stats['total_records'];
    }
    unset($row['traffic_identity_json']);
    $row['current_policy']=event_feature_allowed('api_polling')?fg_relation(fg_cached_config($row['devid'],$row['vd']),$row,$f??[]):null;
    if(!$analysis)foreach(array_keys($row) as $key)if(str_starts_with($key,'av_group')||str_starts_with($key,'security_group')||str_starts_with($key,'security_key')||str_starts_with($key,'traffic_group')||str_starts_with($key,'traffic_key')||$key==='group_key_complete')unset($row[$key]);
    if (isset($row['fields'])) unset($row['fields']);
    return $row;
}
function event_notes(int $eventId): array {
    fg_require_event($eventId);
    return query('SELECT n.id,n.event_id,n.confirmed_recipient,n.confirmation_source,n.body,n.author,n.created_at FROM event_notes n JOIN events ne ON ne.id=n.event_id WHERE '.fg_event_scope('ne').' AND (n.event_id=? OR n.event_id IN (SELECT shared.event_id FROM av_event_groups original JOIN av_event_groups shared ON shared.group_key=original.group_key WHERE original.event_id=?)) ORDER BY n.id DESC LIMIT 100',[$eventId,$eventId]);
}
function av_group_info(int $eventId): ?array {
    fg_require_event($eventId);
    $row=query('SELECT HEX(original.group_key) `key`,original.key_complete,COUNT(*) total_records,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM av_event_groups original JOIN av_event_groups shared ON shared.group_key=original.group_key JOIN events e ON e.id=shared.event_id WHERE '.fg_event_scope('e').' AND original.event_id=? GROUP BY original.group_key,original.key_complete',[$eventId])[0]??null;
    if($row){$row['key_complete']=(bool)$row['key_complete'];$row['total_records']=(int)$row['total_records'];}
    return $row;
}

function security_group_info(int $eventId): ?array {
    fg_require_event($eventId);
    $original=query('SELECT HEX(group_key) `key`,key_complete,identity_json FROM security_event_groups WHERE event_id=?',[$eventId])[0]??null;
    if(!$original)return null;
    $totals=query('SELECT COUNT(*) total_records,MIN(e.event_at) first_event_at,MAX(e.event_at) last_event_at FROM security_event_groups g JOIN events e ON e.id=g.event_id WHERE '.fg_event_scope('e').' AND g.group_key=UNHEX(?)',[$original['key']])[0];
    return ['key'=>$original['key'],'key_complete'=>(bool)$original['key_complete'],'identity'=>json_decode($original['identity_json'],true),'total_records'=>(int)$totals['total_records'],'first_event_at'=>$totals['first_event_at'],'last_event_at'=>$totals['last_event_at']];
}

/** Prime all displayed groups together; exports must not issue one query per row. */
function traffic_group_stats_cache(array $keys): array {
    static $cache=[];
    $keys=array_values(array_unique(array_map('strtoupper',array_filter($keys,fn($key)=>is_string($key)&&$key!==''))));
    foreach($keys as $key)if(!preg_match('/^[A-F0-9]{64}$/D',$key))throw new LogicException('Invalid internal group key');
    $missing=array_values(array_diff($keys,array_keys($cache)));if(!$missing)return $cache;
    require_once __DIR__.'/archive-query.php';
    $pdo=db();$ownsSnapshot=!$pdo->inTransaction();
    if($ownsSnapshot)$pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{
        $watermark=archive_watermark();
        foreach(array_chunk($missing,250) as $chunk){
            $placeholders=implode(',',array_fill(0,count($chunk),'UNHEX(?)'));
            foreach($chunk as $key)$cache[$key]=['total_records'=>0,'first_event_at'=>null,'last_event_at'=>null];
            $raw=$chunk;
            if($watermark!==null){
                $rows=query("SELECT HEX(g.group_key) group_id,SUM(h.records) total_records,MIN(h.first_event_at) first_event_at,MAX(h.last_event_at) last_event_at FROM traffic_groups g STRAIGHT_JOIN archive_group_hours h ON h.group_key=g.group_key STRAIGHT_JOIN archive_dimensions d ON d.id=h.dimension_id WHERE ".fg_identity_scope('g')." AND d.family='t' AND g.group_key IN ($placeholders) GROUP BY g.group_key",$chunk);
                $covered=[];
                foreach($rows as $row){$key=$row['group_id'];$covered[]=$key;unset($row['group_id']);$row['total_records']=(int)$row['total_records'];$cache[$key]=$row;}
                $tail=query("SELECT HEX(g.group_key) group_id,COUNT(*) total_records,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at FROM traffic_event_groups m FORCE INDEX(PRIMARY) STRAIGHT_JOIN traffic_groups g ON g.group_key=m.group_key WHERE m.event_id>? AND ".fg_identity_scope('g')." AND g.group_key IN ($placeholders) GROUP BY g.group_key",[$watermark,...$chunk]);
                foreach($tail as $row){$key=$row['group_id'];$cache[$key]['total_records']+=(int)$row['total_records'];foreach(['first_event_at','last_event_at'] as $field)if($cache[$key][$field]===null||($field==='first_event_at'?$row[$field]<$cache[$key][$field]:$row[$field]>$cache[$key][$field]))$cache[$key][$field]=$row[$field];}
                // A group absent from the rollup may be brand new or legacy data.
                // Read its originals rather than assuming the historical count is zero.
                $raw=array_values(array_diff($chunk,$covered));
            }
            if($raw){
                $placeholders=implode(',',array_fill(0,count($raw),'UNHEX(?)'));
                $rows=query("SELECT HEX(g.group_key) group_id,COUNT(m.event_id) total_records,MIN(m.event_at) first_event_at,MAX(m.event_at) last_event_at FROM traffic_groups g STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(group_time) ON m.group_key=g.group_key WHERE ".fg_identity_scope('g')." AND g.group_key IN ($placeholders) GROUP BY g.group_key",$raw);
                foreach($rows as $row){$key=$row['group_id'];unset($row['group_id']);$row['total_records']=(int)$row['total_records'];$cache[$key]=$row;}
            }
        }
        if($ownsSnapshot)$pdo->commit();return $cache;
    }catch(Throwable $e){if($ownsSnapshot&&$pdo->inTransaction())$pdo->rollBack();throw $e;}
}
function preload_traffic_group_stats(array $rows): void {traffic_group_stats_cache(array_column($rows,'traffic_group_key'));}
function decorate_rows(array $rows): array {if(event_feature_allowed('analysis'))preload_traffic_group_stats($rows);return array_map('decorate',$rows);}
function traffic_group_stats(string $key): array {return traffic_group_stats_cache([$key])[strtoupper($key)];}
function traffic_group_info(int $eventId): ?array {
    fg_require_event($eventId);
    $row=query('SELECT HEX(g.group_key) `key`,g.key_complete,g.identity_json FROM traffic_event_groups m JOIN traffic_groups g ON g.group_key=m.group_key WHERE m.event_id=?',[$eventId])[0]??null;
    return $row?['key'=>$row['key'],'key_complete'=>(bool)$row['key_complete'],'identity'=>json_decode($row['identity_json'],true)]+traffic_group_stats($row['key']):null;
}
function traffic_group_candidates(string $where,array $params,int $limit): array {
    if(trim((string)($_GET['q']??''))!=='') {
        $from='events e JOIN traffic_event_groups m ON m.event_id=e.id';
    }else{
        $reason=block_reason_filter();
        if($reason)[$where,$params]=conditions('e',false,false);
        $from='traffic_groups tg STRAIGHT_JOIN traffic_event_groups m FORCE INDEX(group_time) ON m.group_key=tg.group_key';
        $where=strtr($where,['e.event_at'=>'m.event_at','e.policyid'=>'tg.policyid','e.profile'=>'m.profile','e.subtype'=>'tg.subtype','e.srcip'=>'tg.srcip','e.reason_code'=>'tg.reason_code','e.outcome'=>'tg.outcome','e.rating_error'=>'0','e.devid'=>"JSON_UNQUOTE(JSON_EXTRACT(tg.identity_json,'$.devid'))",'e.vd'=>"JSON_UNQUOTE(JSON_EXTRACT(tg.identity_json,'$.vd'))"]);
        if($reason){$where.=' AND '.block_reason_hash_sql('tg.subtype',"JSON_EXTRACT(tg.identity_json,'$.reason')").'=?';$params[]=$reason[1];}
    }
    $matched="SELECT m.event_id id,m.event_at,m.group_key FROM $from WHERE $where";
    $stats="SELECT group_key,COUNT(*) matched_records,MIN(event_at) first_event_at,MAX(event_at) last_event_at FROM matched GROUP BY group_key";
    $totals=query("WITH matched AS ($matched),stats AS ($stats) SELECT COUNT(*) groups_count,COALESCE(SUM(matched_records),0) records FROM stats",$params)[0];
    $keys=query("WITH matched AS ($matched),stats AS ($stats) SELECT MAX(m.id) id,s.last_event_at event_at,'traffic' group_kind,s.matched_records,s.first_event_at,s.last_event_at FROM stats s STRAIGHT_JOIN matched m ON m.group_key=s.group_key AND m.event_at=s.last_event_at GROUP BY s.group_key,s.matched_records,s.first_event_at,s.last_event_at ORDER BY event_at DESC,id DESC LIMIT $limit",$params);
    return ['keys'=>$keys,'records'=>(int)$totals['records'],'groups_count'=>(int)$totals['groups_count']];
}
