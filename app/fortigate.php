<?php
declare(strict_types=1);
const FG_CACHE_ROOT='/srv/fls-server/metrics/fortigate';
const FG_SERIAL='FGT0000000000000';
require_once __DIR__.'/connections.php';
const FG_PROFILE_KINDS=['virus','webfilter','app-ctrl','dns','ips','ssl'];

function fg_snapshot(string $name,?string $root=null): array {
    if(!in_array($name,['live','config'],true))return [];
    $path=($root??fg_root()).'/'.$name.'.json';$size=@filesize($path);
    if($size===false || $size>16777216)return [];
    $value=json_decode(@file_get_contents($path)?:'null',true);
    return is_array($value)&&($value['schema']??null)===1&&($value['device']['serial']??'')===fg_serial()&&($value['device']['vdom']??'')===fg_vdom()&&is_array($value['components']??null)?fg_snapshot_state($value):[];
}
function fg_snapshot_state(array $value): array {
    $d=fg_selected_device();
    if(empty($d['enabled'])||empty($d['active_keys']))foreach($value['components'] as &$c){$c['error']=empty($d['enabled'])?'connection_disabled':'no_credentials';$c['availability']=['state'=>'unknown','reason'=>$c['error']];}
    return $value;
}
function fg_component(array $snapshot,string $name,int $ttl,?int $now=null): array {
    $component=$snapshot['components'][$name]??[];$at=$component['observed_at']??null;$time=$at?strtotime($at):false;
    $age=$time!==false?max(0,($now??time())-$time):null;
    $availability=$component['availability']??[];$state=$availability['state']??'unknown';
    if(!in_array($state,['available','disabled','unsupported','permission_denied','authentication_failed','temporary_error','unknown'],true))$state='unknown';
    if(($component['error']??null)==='http_401')$state='authentication_failed';if(($component['error']??null)==='http_403')$state='permission_denied';
    $checked=strtotime($availability['checked_at']??'');$cap=$component['capability_identity']??[];
    $availabilityFresh=$checked!==false&&$checked<=($now??time())+30&&($now??time())-$checked<=$ttl;
    if(in_array($state,['disabled','unsupported'],true))$availabilityFresh=$availabilityFresh&&($cap['serial']??null)===($snapshot['device']['serial']??null)&&($cap['vdom']??null)===($snapshot['device']['vdom']??null);
    return ['availability'=>['state'=>$state,'reason'=>$availability['reason']??null,'fresh'=>$availabilityFresh],'observed_at'=>$at,'attempted_at'=>$component['attempted_at']??null,'age_seconds'=>$age,
            'fresh'=>$age!==null&&$age<=$ttl&&empty($component['error'])&&$time<=($now??time())+30,
            'error'=>$component['error']??($age===null?'not_sampled':null),'data'=>$component['data']??null];
}
function fg_resolve_policy(array $policy,array $groups): array {
    $policy['profiles_resolved']=true;
    if(($policy['profile-type']??'')==='group'){
        $found=false;foreach($groups['data']??[] as $group)if(($group['name']??'')===($policy['profile-group']??'')){
            $policy['profiles']=$group['profiles'];$found=true;break;
        }
        $policy['profiles_resolved']=$found&&$groups['fresh'];
    }
    return $policy;
}
function fg_config_data(?array $snapshot=null,?int $now=null): array {
    $snapshot??=fg_snapshot('config');$health=[];
    foreach(array_merge(['policies','profile_groups','categories','url_filters'],array_map(fn($v)=>'profiles_'.$v,FG_PROFILE_KINDS)) as $key){
        $health[$key]=fg_component($snapshot,$key,660,$now);
    }
    $policies=[];foreach($health['policies']['data']??[] as $p)$policies[]=fg_resolve_policy($p,$health['profile_groups']);
    $profiles=[];foreach(FG_PROFILE_KINDS as $kind)$profiles[$kind]=$health['profiles_'.$kind]['data']??[];
    foreach($policies as &$p)$p['history_key']=hash('sha256','policy:'.$p['policyid'].':'.strtolower($p['uuid']));unset($p);
    foreach($profiles as $kind=>&$items){foreach($items as &$p)$p['history_key']=hash('sha256','profiles_'.$kind.':'.$p['name']);unset($p);}unset($items);
    foreach($profiles['webfilter'] as &$p){
        $id=$p['url_filter_table']??0;if(!$id)continue;
        $table=null;foreach($health['url_filters']['data']??[] as $entry)if($entry['id']===$id){$table=$entry;break;}
        $p['static_url_filter']=['table'=>$table,'fresh'=>$health['url_filters']['fresh'],'observed_at'=>$health['url_filters']['observed_at']];
    }unset($p);
    foreach($health as &$item)unset($item['data']);unset($item);
    return ['device'=>['serial'=>fg_serial(),'vdom'=>fg_vdom(),'name'=>fg_selected_device()['name'],'id'=>(int)fg_selected_device()['id']],'updated_at'=>$snapshot['updated_at']??null,
            'policies'=>$policies,'profiles'=>$profiles,'categories'=>$snapshot['components']['categories']['data']??[],
            'health'=>$health,'refresh_seconds'=>300,
            'note'=>'API şu anki yapılandırmayı gösterir. Geçmiş olay anındaki ayarların kanıtı değildir.'];
}
function fg_cached_config(?string $serial=null,?string $vdom=null): array {
    static $values;
    $d=$serial===null?fg_selected_device():fg_event_device(['devid'=>$serial,'vd'=>$vdom]);$key=$d['serial'].'|'.$d['vdom'];
    return $values[$key]??=fg_with_device($d,fn()=>fg_config_data());
}

/** Relate history only on device + VDOM + IPv4 policy scope + ID + UUID. */
function fg_relation(array $config,array $event,array $fields=[],bool $detail=false): array {
    $health=$config['health']['policies']??[];
    $result=['status'=>'unavailable','fresh'=>(bool)($health['fresh']??false),'observed_at'=>$health['observed_at']??null,
             'message'=>'Güncel policy bilgisi henüz alınamadı.','log_profile'=>(string)($event['profile']??''),
             'current_name'=>null,'assigned_profile'=>null,'profile_changed'=>null,'log_profile_available'=>false];
    if(($event['devid']??'')!==($config['device']['serial']??'') || ($event['vd']??'')!==($config['device']['vdom']??'')){
        $result['status']='device_scope';$result['message']='Bu cihaz / VDOM için güncel yapılandırma bağlı değil.';return $result;
    }
    if(($event['subtype']??'')==='local' || !in_array((string)($fields['policytype']??'policy'),['','policy'],true)){
        $result['status']='policy_scope';$result['message']='Bu kayıt local / farklı policy kapsamındadır; IPv4 firewall policy listesiyle eşleştirilmez.';return $result;
    }
    $id=$event['policyid']??-1;
    if((string)$id==='0'){$result['status']='implicit';$result['message']='Policy 0: açık bir firewall policy nesnesiyle eşleştirilmez.';return $result;}
    $kind=(string)($event['subtype']??'');$profile=null;
    if(in_array($kind,FG_PROFILE_KINDS,true)&&$result['log_profile']!==''){
        foreach($config['profiles'][$kind]??[] as $p)if($p['name']===$result['log_profile']){$profile=$p;break;}
        $profileHealth=$config['health']['profiles_'.$kind]??[];
        $result['log_profile_available']=$profile!==null;$result['log_profile_fresh']=(bool)($profileHealth['fresh']??false);
        $result['profile_observed_at']=$profileHealth['observed_at']??null;
        if($detail && $profile!==null)$result['log_profile_details']=$profile;
    }
    $uuid=strtolower((string)($event['poluuid']??''));
    if(!preg_match('/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/D',$uuid)){
        $result['status']='uuid_missing';$result['message']='Logda geçerli policy UUID yok; yalnız ID ile güncel policy eşleştirilmedi.';return $result;
    }
    $policy=null;foreach($config['policies']??[] as $p)if((string)$p['policyid']===(string)$id){$policy=$p;break;}
    if($policy===null){
        if($result['fresh']){$result['status']='not_found';$result['message']='Bu policy ID güncel listede bulunmuyor; geçmiş kayıt korunuyor.';}
        return $result;
    }
    if(strtolower($policy['uuid'])!==$uuid){$result['status']='uuid_mismatch';$result['message']='Policy ID aynı, UUID farklı; güncel nesne bu geçmiş olayla eşleştirilmedi.';return $result;}
    $result['status']='matched';$result['current_name']=$policy['name'];$result['policy_status']=$policy['status'];
    $result['utm_enabled']=$policy['utm-status']==='enable';$result['profiles_resolved']=$policy['profiles_resolved'];
    if($policy['profiles_resolved']&&in_array($kind,FG_PROFILE_KINDS,true)){
        $result['assigned_profile']=$policy['profiles'][$kind]??'';
        $result['profile_changed']=$result['log_profile']!==''&&$result['assigned_profile']!==$result['log_profile'];
    }
    $result['message']=$result['fresh']?'Cihaz, VDOM, policy ID ve UUID güncel nesneyle eşleşti.':'Kimlik son başarılı kopyayla eşleşti; yapılandırma güncel olarak doğrulanamıyor.';
    if($detail)$result['policy']=$policy;
    return $result;
}

function fg_live_data(?string $root=null,?int $now=null): array {
    $now??=time();$snapshot=fg_snapshot('live',$root);$components=[];
    foreach(['inventory','ha','sdwan_settings','resources','performance','ipsec','ssl_vpn','sdwan_health','sdwan_members'] as $name)$components[$name]=fg_component($snapshot,$name,95,$now);
    $points=[];$directory=$root??fg_root();
    foreach(array_unique([gmdate('Y-m-d',$now-3600),gmdate('Y-m-d',$now)]) as $day){
        $file=$directory.'/'.$day.'.jsonl';$size=@filesize($file);if($size===false||$size>2097152)continue;
        $stream=@fopen($file,'rb');if(!$stream)continue;
        try{while(($line=fgets($stream,4097))!==false){
            if(!str_ends_with($line,"\n"))continue;$r=json_decode($line,true);if(!is_array($r)||!is_string($r['at']??null))continue;
            $at=strtotime($r['at']);if($at===false||$at<$now-3600||$at>$now+30)continue;
            $point=['at'=>$r['at'],'gap'=>false];foreach(['cpu_percent','memory_percent'] as $k){$v=$r[$k]??null;$point[$k]=(is_int($v)||is_float($v))&&is_finite((float)$v)&&$v>=0&&$v<=100?$v:null;}
            $points[$at]=$point;
        }}finally{fclose($stream);}
    }
    ksort($points);$last=null;foreach($points as $at=>&$point){$point['gap']=$last!==null&&$at-$last>95;$last=$at;}unset($point);
    return ['device'=>['serial'=>fg_serial(),'vdom'=>fg_vdom(),'name'=>fg_selected_device()['name'],'id'=>(int)fg_selected_device()['id']],'updated_at'=>$snapshot['updated_at']??null,'components'=>$components,
            'inventory'=>$components['inventory'],'ha'=>$components['ha'],'history'=>array_values(array_slice($points,-180,null,true)),'refresh_seconds'=>30,'history_seconds'=>3600,
            'note'=>'Canlı durum son API örneğidir; tarih filtresinden bağımsızdır. VPN rapor sürelerine eklenmez.'];
}
