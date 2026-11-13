<?php
declare(strict_types=1);

/** Pure, conservative projection. These records are evidence, never proof of a web visit. */
const FLS_ALLOWED_MODEL_VERSION=1;
const FLS_ALLOWED_IDENTITY_COLUMNS=['devid','vd','srcip','policyid','poluuid','profile','subtype','evidence_kind','action','target_kind','target_value','dstip','dstport','proto','app','category','risk','web_observation'];
const FLS_ALLOWED_FORWARD_ACTIONS=['accept','close','timeout','client-rst','server-rst'];
const FLS_ALLOWED_UTM_ACTIONS=[
    'webfilter'=>['pass','passthrough','monitor','allow'],
    'app-ctrl'=>['pass','monitor','allow'],
    'dns'=>['pass','monitor','allow'],
    'ssl'=>['pass','passthrough','monitor','allow','bypass'],
    'virus'=>['pass','passthrough','monitor','allow','bypass'],
    'ips'=>['pass','pass_session','monitor','allow'],
];

/** Cheap indexed-column gate, before any original JSON decoding. */
function allowed_model_primary(array $event): bool {
    $valid=true;$type=strtolower(allowed_model_text($event['type']??'',24,$valid));$module=strtolower(allowed_model_text($event['subtype']??'',40,$valid));$action=strtolower(allowed_model_text($event['action']??'',48,$valid));
    if(!$valid||in_array($event['outcome']??'',['security_block','policy_deny','local_deny','other_deny','rating_error'],true)||(int)($event['rating_error']??0)!==0)return false;
    return $type==='traffic'?$module==='forward'&&in_array($action,FLS_ALLOWED_FORWARD_ACTIONS,true):($type==='utm'&&isset(FLS_ALLOWED_UTM_ACTIONS[$module])&&in_array($action,FLS_ALLOWED_UTM_ACTIONS[$module],true));
}

function allowed_model_text(mixed $value,int $maximum,bool &$complete,bool $trim=true): string {
    if($value===null)return '';
    if(!is_string($value)&&!is_int($value)){$complete=false;return '';}
    $value=$trim?trim((string)$value):(string)$value;
    if(!mb_check_encoding($value,'UTF-8')||mb_strlen($value)>$maximum||preg_match('/[\x00-\x1f\x7f]/u',$value)){$complete=false;return '';}
    return $value;
}
function allowed_model_integer(mixed $value,int $minimum,int $maximum): ?int {
    if(!is_int($value)&&(!is_string($value)||!preg_match('/^-?[0-9]+$/D',$value)))return null;
    $number=filter_var($value,FILTER_VALIDATE_INT);
    return $number!==false&&$number>=$minimum&&$number<=$maximum?$number:null;
}
function allowed_model_blocking(string $value): bool {
    $blocked=['blocked','block','deny','denied','dropped','drop','blocked-quota','block-fail','block-servfail','reset','reset_client','reset_server','reset-client','reset-server','drop_session','drop-session'];
    foreach(preg_split('~[\s,;|/]+~',strtolower(trim($value)))?:[] as $part)if(in_array($part,$blocked,true))return true;
    return false;
}
function allowed_model_evidence(array $event,array $fields): ?string {
    $valid=true;$type=strtolower(allowed_model_text($event['type']??$fields['type']??'',24,$valid));
    $module=strtolower(allowed_model_text($event['subtype']??$fields['subtype']??'',40,$valid));
    $action=strtolower(allowed_model_text($event['action']??$fields['action']??'',48,$valid));
    if(!$valid||in_array($event['outcome']??'',['security_block','policy_deny','local_deny','other_deny','rating_error'],true)||(int)($event['rating_error']??0)!==0)return null;
    foreach(['action','utmaction','appact'] as $key){
        $value=allowed_model_text($fields[$key]??'',64,$valid);
        if(!$valid||allowed_model_blocking($value))return null;
        if($key!=='action'&&$value!=='')foreach(preg_split('~[\s,;|/]+~',strtolower($value))?:[] as $part)if(!in_array($part,['allow','pass','passthrough','monitor','bypass','pass_session','none'],true))return null;
    }
    $eventType=strtolower(allowed_model_text($fields['eventtype']??'',64,$valid));
    if(!$valid||$eventType==='ftgd_err')return null;
    if($type==='traffic')return $module==='forward'&&in_array($action,FLS_ALLOWED_FORWARD_ACTIONS,true)?'traffic':null;
    if($type!=='utm')return null;
    if(!isset(FLS_ALLOWED_UTM_ACTIONS[$module])||!in_array($action,FLS_ALLOWED_UTM_ACTIONS[$module],true))return null;
    return ['webfilter'=>'web','app-ctrl'=>'app','dns'=>'dns','ssl'=>'tls','virus'=>'security','ips'=>'security'][$module];
}
function allowed_model_host(mixed $raw): ?array {
    if(!is_string($raw)||!mb_check_encoding($raw,'UTF-8'))return null;
    $host=trim(str_replace('\\:',':',$raw));
    if($host===''||strlen($host)>4096||preg_match('/[\x00-\x20\x7f]/u',$host))return null;
    if(preg_match('~^https?://~i',$host))$host=parse_url($host,PHP_URL_HOST)?:'';
    elseif(str_contains($host,':')&&!filter_var(trim($host,'[]'),FILTER_VALIDATE_IP))$host=parse_url('https://'.$host,PHP_URL_HOST)?:'';
    $host=trim($host,'[]');
    if(filter_var($host,FILTER_VALIDATE_IP))return ['kind'=>'ip','value'=>inet_ntop(inet_pton($host))];
    $host=mb_strtolower(rtrim($host,'.'),'UTF-8');
    if($host===''||strlen($host)>253)return null;
    foreach(explode('.',$host) as $label)if($label===''||strlen($label)>63||!preg_match('/^[\p{L}\p{N}_](?:[\p{L}\p{N}_-]*[\p{L}\p{N}_])?$/uD',$label))return null;
    return ['kind'=>'domain','value'=>$host];
}
function allowed_model_risk(array $fields): string {
    $levels=['unknown'=>0,'low'=>1,'elevated'=>2,'medium'=>3,'high'=>4,'critical'=>5];$result='unknown';
    foreach(['apprisk','crlevel'] as $key){$value=$fields[$key]??'';if(!is_string($value))continue;$value=strtolower(trim($value));if(isset($levels[$value])&&$levels[$value]>$levels[$result])$result=$value;}
    return $result;
}
/** Source values are never truncated into shared identities. Missing identities are event-isolated. */
function allowed_model_projection(array $event): ?array {
    if(!allowed_model_primary($event))return null;
    $fields=$event['fields']??[];
    if(is_string($fields)){try{$fields=json_decode($fields,true,64,JSON_THROW_ON_ERROR);}catch(Throwable){return null;}}
    if(!is_array($fields))return null;
    $evidence=allowed_model_evidence($event,$fields);if($evidence===null)return null;
    $complete=true;$projection=[];
    $category=($event['subtype']??'')==='app-ctrl'?($fields['appcat']??$fields['catdesc']??null):($fields['catdesc']??$fields['appcat']??null);
    foreach(['devid'=>40,'vd'=>64,'srcip'=>45,'poluuid'=>40,'profile'=>160,'subtype'=>40,'action'=>48,'dstip'=>45,'app'=>160,'category'=>160] as $key=>$maximum){
        $original=$fields[$key]??($key==='profile'?($fields['applist']??$fields['sensor']??null):($key==='category'?$category:null));
        $projection[$key]=allowed_model_text($original??$event[$key]??'',$maximum,$complete,!in_array($key,['profile','app','category'],true));
    }
    foreach(['subtype','action'] as $key)$projection[$key]=strtolower($projection[$key]);
    foreach(['srcip','dstip'] as $key){if(filter_var($projection[$key],FILTER_VALIDATE_IP))$projection[$key]=inet_ntop(inet_pton($projection[$key]));elseif($projection[$key]!==''){$complete=false;$projection[$key]='';}}
    $projection['policyid']=allowed_model_integer($fields['policyid']??$event['policyid']??null,0,2147483647)??-1;
    $projection['dstport']=allowed_model_integer($fields['dstport']??$event['dstport']??null,0,65535);
    $proto=allowed_model_integer($fields['proto']??null,0,255);$projection['proto']=$proto===null?'':(string)$proto;
    $projection['evidence_kind']=$evidence;$projection['risk']=allowed_model_risk($fields);
    $host=null;$candidates=$projection['subtype']==='dns'?['qname']:($projection['subtype']==='ssl'?['sni','hostname','servername']:['hostname','sni','servername']);
    foreach($candidates as $key){$value=$fields[$key]??($key==='hostname'?($event['hostname']??null):null);if($value===null||$value==='')continue;$candidate=allowed_model_host($value);if($candidate!==null){$host=$candidate;break;}$complete=false;}
    if($host===null&&$projection['subtype']==='webfilter'&&is_string($fields['url']??null)&&preg_match('~^https?(?:\\\\)?:~i',$fields['url']))$host=allowed_model_host($fields['url']);
    $target=$host??($projection['dstip']!==''&&$projection['subtype']!=='dns'?['kind'=>'ip','value'=>$projection['dstip']]:['kind'=>'missing','value'=>'']);
    $projection['target_kind']=$target['kind'];$projection['target_value']=$target['value'];
    $projection['target_json']=json_encode($target,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $projection['target_key']=hash('sha256',$projection['target_json'],true);
    $service=is_string($fields['service']??null)?strtoupper(trim($fields['service'])):'';
    $webPort=in_array($projection['proto'],['6','17'],true)&&(in_array($projection['dstport'],[80,443,8080,8443],true)||in_array($service,['HTTP','HTTPS'],true));
    $projection['web_observation']=(int)(in_array($target['kind'],['domain','ip'],true)&&($evidence==='web'||$host!==null&&in_array($evidence,['tls','traffic'],true)&&$webPort));
    $complete=$complete&&$projection['devid']!==''&&$projection['vd']!==''&&filter_var($projection['srcip'],FILTER_VALIDATE_IP)!==false&&$projection['policyid']>=0&&$target['kind']!=='missing';
    $policyType=allowed_model_text($fields['policytype']??'',64,$complete);
    $identity=[FLS_ALLOWED_MODEL_VERSION];foreach(FLS_ALLOWED_IDENTITY_COLUMNS as $key)$identity[]=$projection[$key];$identity[]=$policyType;
    $eventId=(string)($event['event_id']??$event['id']??'');
    if(!$complete){if(!preg_match('/^[1-9][0-9]{0,19}$/D',$eventId))return null;$identity[]='incomplete-event';$identity[]=$eventId;}
    $projection['fingerprint']=hash('sha256',json_encode($identity,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),true);
    return $projection;
}
