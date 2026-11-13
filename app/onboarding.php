<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';

function onboarding_ipv4(array $data,string $field): string {
    $ip=management_ip(management_text($data,$field,15));
    if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))throw new ManagementError('Bu alıcı için IPv4 adresi girin.');
    return $ip;
}
function onboarding_admin(): void {
    if(($_SESSION['role']??'')!=='admin')throw new ManagementError('Kurulum yönetici yetkisi gerektirir.',403);
}
function onboarding_write(string $route,array $data): array {
    onboarding_admin();$id=management_int($data,'connection_id');$pdo=db();$pdo->beginTransaction();
    try{
        query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
        $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$_SESSION['uid']])[0]??null;
        if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti.',403);
        $device=query('SELECT id,vdom FROM fortigate_connections WHERE id=?',[$id])[0]??null;if(!$device)throw new ManagementError('Cihaz bulunamadı.',404);
        $old=query('SELECT * FROM fortigate_setup WHERE connection_id=? FOR UPDATE',[$id])[0]??null;
        $revision=management_int($data,'revision',0);
        if($revision!==($old?(int)$old['revision']:0))throw new ManagementError('Kurulum başka bir oturumda değişti. Yenileyin.',409);
        $baseline=query('SELECT COALESCE(MAX(id),0) id FROM events')[0]['id'];
        if($route==='save_fortigate_setup'){
            $source=onboarding_ipv4($data,'source_ip');$peer=onboarding_ipv4($data,'peer_ip');$receiver=onboarding_ipv4($data,'receiver_ip');
            $trust=onboarding_ipv4($data,'api_trust_ip');
            $slot=management_int($data,'syslog_slot',1,4);$scope=management_enum($data,'cli_scope',['single','override']);$confirmed=management_bool($data,'override_confirmed');$admit=management_bool($data,'receiver_admitted');
            if($scope==='single'&&$device['vdom']!=='root')throw new ManagementError('root dışındaki VDOM için VDOM override kapsamını seçin.');
            execute('INSERT INTO fortigate_setup(connection_id,source_ip,peer_ip,receiver_ip,api_trust_ip,syslog_slot,cli_scope,override_confirmed,receiver_admitted,baseline_event_id,test_started_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE source_ip=VALUES(source_ip),peer_ip=VALUES(peer_ip),receiver_ip=VALUES(receiver_ip),api_trust_ip=VALUES(api_trust_ip),syslog_slot=VALUES(syslog_slot),cli_scope=VALUES(cli_scope),override_confirmed=VALUES(override_confirmed),receiver_admitted=VALUES(receiver_admitted),baseline_event_id=VALUES(baseline_event_id),test_started_at=VALUES(test_started_at),updated_at=VALUES(updated_at),revision=revision+1',[$id,$source,$peer,$receiver,$trust,$slot,$scope,$confirmed,$admit,$baseline]);
        }else{
            if(!$old)throw new ManagementError('Önce log kaynağını kaydedin.');
            execute('UPDATE fortigate_setup SET revision=revision+1,baseline_event_id=?,test_started_at=UTC_TIMESTAMP(6),updated_at=UTC_TIMESTAMP(6) WHERE connection_id=?',[$baseline,$id]);
            execute("UPDATE fortigate_credentials SET test_requested_at=UTC_TIMESTAMP(6),check_status='pending',check_code=NULL WHERE connection_id=? AND enabled=1",[$id]);
        }
        audit($route,'connection_id='.$id);$pdo->commit();return ['saved'=>true,'id'=>$id];
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
function onboarding_collector(): array {
    $path='/srv/fls-server/metrics/fortigate-onboarding.json';
    $text=@file_get_contents($path,false,null,0,65537);$s=is_string($text)&&strlen($text)<65536?json_decode($text,true):null;
    if(!is_array($s)||($s['schema']??null)!==1)return ['fresh'=>false,'error'=>'worker_unavailable'];
    $age=time()-(strtotime(($s['updated_at']??'').' UTC')?:0);$s['fresh']=$age>=-30&&$age<=90;return $s;
}
function onboarding_components(array $device,string $mode,array $names,int $ttl,int $floor=0): array {
    $base='/srv/fls-server/metrics/fortigate';if(!(int)$device['legacy_cache'])$base.='/devices/'.(int)$device['id'];
    $text=@file_get_contents($base.'/'.$mode.'.json',false,null,0,16*1024*1024+1);$s=is_string($text)&&strlen($text)<16*1024*1024?json_decode($text,true):null;$valid=is_array($s)&&($s['schema']??null)===1&&($s['device']['serial']??null)===$device['serial']&&($s['device']['vdom']??null)===$device['vdom'];
    $rows=[];
    foreach($names as $key=>$label){
        $c=$valid?($s['components'][$key]??[]):[];$age=time()-(strtotime($c['observed_at']??'')?:0);$ok=!empty($c['observed_at'])&&(strtotime($c['observed_at'])?:0)>=$floor&&$age>=-30&&$age<=$ttl&&empty($c['error'])&&array_key_exists('data',$c);
        $availability=$c['availability']??[];$state=$availability['state']??($ok?'available':'unknown');$checked=strtotime($availability['checked_at']??'')?:0;
        $cap=$c['capability_identity']??[];$optional=in_array($key,['ipsec','ssl_vpn','sdwan_health','sdwan_members','ha','profile_groups','profiles_virus','profiles_webfilter','profiles_app-ctrl','profiles_dns','profiles_ips','profiles_ssl'],true);
        $notApplicable=$valid&&$optional&&(($state==='unsupported'&&in_array($c['error']??null,['http_404','http_405','http_501'],true))||($state==='disabled'&&empty($c['error'])))&&$checked>=$floor&&time()-$checked>=-30&&time()-$checked<=$ttl&&($cap['serial']??null)===$device['serial']&&($cap['vdom']??null)===$device['vdom'];
        $rows[]=['availability'=>$state,'satisfied'=>$ok||$notApplicable,'name'=>$key,'label'=>$label,'ok'=>$ok,'error'=>$c['error']??null,'observed_at'=>$c['observed_at']??null,'count'=>$ok&&is_array($c['data'])&&array_is_list($c['data'])?count($c['data']):null];
    }
    return $rows;
}
function onboarding_commands(array $d,?array $s): array {
    if(!$s)return [];
    // All interpolated values are strict IPv4, slot integers or the immutable validated VDOM.
    if(!preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D',$d['vdom']))return [];
    foreach(['source_ip','receiver_ip'] as $key)if(!filter_var($s[$key],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))return [];
    $slot=(int)$s['syslog_slot'];if($slot<1||$slot>4)return [];
    $name='syslogd'.($slot===1?'':$slot);$override=$s['cli_scope']==='override';$scope=$override?'override-setting':'setting';$filter=$override?'override-filter':'filter';
    $preflight=['get system status'];
    if($override)$preflight=array_merge($preflight,['config vdom','edit "'.$d['vdom'].'"','show full-configuration log setting']);
    for($i=1;$i<=4;$i++)$preflight[]='show log syslogd'.($i===1?'':$i).' '.$scope;
    if($override)$preflight=array_merge($preflight,['next','end']);
    $apply=[];
    if(!$override||(int)$s['override_confirmed']){
        if($override)$apply=['config vdom','edit "'.$d['vdom'].'"'];
        $apply=array_merge($apply,['config log '.$name.' '.$scope,'set status enable','set server "'.$s['receiver_ip'].'"','set mode reliable','set port 5514','set format default','set enc-algorithm disable','set source-ip "'.$s['source_ip'].'"','end','config log '.$name.' '.$filter,'set severity information','set forward-traffic enable','set local-traffic enable','end','show log '.$name.' '.$scope,'show log '.$name.' '.$filter]);
        if($override)$apply=array_merge($apply,['next','end']);
    }
    $profile='FLS_RO_'.(int)$d['id'];$user='FLS_API_'.(int)$d['id'];$api=[];
    if($override)$api[]='config global';
    $api=array_merge($api,['config system accprofile','edit "'.$profile.'"','set comments "FLS read-only monitoring"','set fwgrp read','set utmgrp read','set vpngrp read','set netgrp read','set sysgrp read','set authgrp none','set loggrp none','set ftviewgrp none','set secfabgrp none','set wifi none','set cli-config disable','set cli-exec disable','set cli-diagnose disable','next','end','config system api-user','edit "'.$user.'"','set accprofile "'.$profile.'"','set vdom "'.$d['vdom'].'"','config trusthost','edit 1','set ipv4-trusthost '.$s['api_trust_ip'].' 255.255.255.255','next','end','next','end','execute api-user generate-key '.$user]);
    if($override)$api[]='end';
    return ['preflight'=>implode("\n",$preflight),'apply'=>implode("\n",$apply),'api_preflight'=>'show system accprofile "'.$profile.'"'."\n".'show system api-user "'.$user.'"','api'=>implode("\n",$api)];
}
function onboarding_snapshot(array $input): array {
    onboarding_admin();$id=management_int($input,'connection_id');
    $d=query('SELECT id,name,serial,vdom,hostname,connect_ip,port,enabled,legacy_cache,updated_at FROM fortigate_connections WHERE id=?',[$id])[0]??null;if(!$d)throw new ManagementError('Cihaz bulunamadı.',404);
    $s=query('SELECT * FROM fortigate_setup WHERE connection_id=?',[$id])[0]??null;$r=query('SELECT * FROM fortigate_setup_receipts WHERE connection_id=?',[$id])[0]??null;$collector=onboarding_collector();
    if($r&&(!$s||(int)$r['setup_revision']!==(int)$s['revision']))$r=null;
    $keys=query('SELECT id,name,purpose,enabled,revision,checked_revision,check_status,check_code,checked_at,updated_at FROM fortigate_credentials WHERE connection_id=? ORDER BY priority,id',[$id]);
    $floor=strtotime($d['updated_at'].' UTC')?:0;foreach($keys as $k)$floor=max($floor,strtotime($k['updated_at'].' UTC')?:0);if($s)$floor=max($floor,strtotime($s['test_started_at'].' UTC')?:0);
    $live=onboarding_components($d,'live',['resources'=>'CPU / RAM','ipsec'=>'IPsec VPN','ssl_vpn'=>'SSL VPN','sdwan_health'=>'SD-WAN sağlık','sdwan_members'=>'SD-WAN üyeleri'],120,$floor);
    $config=onboarding_components($d,'config',['policies'=>'Firewall policy','profile_groups'=>'Profil grupları','profiles_virus'=>'Antivirüs','profiles_webfilter'=>'Web filtresi','profiles_app-ctrl'=>'Uygulama kontrolü','profiles_dns'=>'DNS filtresi','profiles_ips'=>'IPS','profiles_ssl'=>'SSL / SSH'],660,$floor);
    $inventory=onboarding_components($d,'live',['inventory'=>'Cihaz envanteri','ha'=>'HA'],120,$floor);
    $base='/srv/fls-server/metrics/fortigate';if(!(int)$d['legacy_cache'])$base.='/devices/'.(int)$d['id'];$raw=@file_get_contents($base.'/live.json',false,null,0,16*1024*1024+1);$cache=is_string($raw)&&strlen($raw)<16*1024*1024?json_decode($raw,true):null;
    $inventoryData=is_array($cache)&&($cache['device']['serial']??null)===$d['serial']&&($cache['device']['vdom']??null)===$d['vdom']?($cache['components']['inventory']['data']??null):null;
    $haData=is_array($cache)&&($cache['device']['serial']??null)===$d['serial']&&($cache['device']['vdom']??null)===$d['vdom']?($cache['components']['ha']['data']??null):null;
    $admitted=$s&&($collector['fresh']??false)&&empty($collector['error'])&&in_array($s['peer_ip'],$collector['allowed_ips']??[],true);
    $receiptAge=$r?time()-(strtotime($r['received_at'].' UTC')?:0):PHP_INT_MAX;
    $receiptOk=$admitted&&$r&&$r['status']==='ok'&&$r['peer_ip']===$s['peer_ip']&&$receiptAge>=-30&&$receiptAge<=300;
    $liveOk=(bool)$d['enabled']&&!array_filter($live,fn($c)=>!$c['satisfied']);$configOk=(bool)$d['enabled']&&!array_filter($config,fn($c)=>!$c['satisfied']);
    $keyOk=false;foreach($keys as $k)if((int)$k['enabled']&&$k['check_status']==='ok'&&(int)$k['revision']===(int)$k['checked_revision']&&(strtotime(($k['checked_at']??'').' UTC')?:0)>=$floor&&time()-(strtotime(($k['checked_at']??'').' UTC')?:0)>=-30&&time()-(strtotime(($k['checked_at']??'').' UTC')?:0)<=600)$keyOk=true;
    $apiOk=$keyOk||($liveOk&&$configOk);$cliOk=$s&&($s['cli_scope']==='single'||(int)$s['override_confirmed']);
    $access=(bool)query('SELECT connection_id FROM user_fortigate_access WHERE user_id=? AND connection_id=?',[(int)$_SESSION['uid'],$id]);
    return ['device'=>$d,'setup'=>$s,'receipt'=>$r,'collector'=>$collector,'credentials'=>$keys,'inventory'=>$inventory,'inventory_data'=>$inventoryData,'ha_data'=>$haData,'live'=>$live,'config'=>$config,'commands'=>onboarding_commands($d,$s),'can_inspect'=>$access,'checks'=>['api'=>$apiOk,'live'=>$liveOk,'config'=>$configOk,'receiver'=>(bool)$admitted,'log'=>(bool)$receiptOk,'ready'=>(bool)($apiOk&&$liveOk&&$configOk&&$receiptOk&&$cliOk)],'checked_at'=>gmdate('Y-m-d H:i:s')];
}
