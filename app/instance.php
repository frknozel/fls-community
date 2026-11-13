<?php
declare(strict_types=1);
/** Public installation metadata. Root owns this file; it contains no API or signing secrets. */
function fls_instance(): array {
    static $value;if($value!==null)return $value;
    $empty=['configured'=>false,'installation_id'=>null,'hostname'=>null,'bind_ip'=>null,'collector_ip'=>null,'collector_port'=>5514,'timezone'=>'Europe/Istanbul','storage_label'=>null,'data_path'=>'/srv/fortigate'];
    $raw=@file_get_contents('/etc/fls/instance.json',false,null,0,16385);$d=is_string($raw)&&strlen($raw)<=16384?json_decode($raw,true):null;
    if(!is_array($d)||($d['schema']??null)!==1||!is_string($d['installation_id']??null)||!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D',$d['installation_id']))return $value=$empty;
    foreach(['bind_ip','collector_ip'] as $key)if(!is_string($d[$key]??null)||!filter_var($d[$key],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))return $value=$empty;
    if(!is_string($d['hostname']??null)||!filter_var($d['hostname'],FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)||($d['collector_port']??null)!==5514||($d['timezone']??null)!=='Europe/Istanbul'||($d['data_path']??null)!=='/srv/fortigate'||!is_string($d['storage_label']??null)||mb_strlen($d['storage_label'])>80)return $value=$empty;
    return $value=['configured'=>true]+array_intersect_key($d,$empty);
}
function fls_receiver_state(): array {
    $raw=@file_get_contents('/srv/fortigate/metrics/fortigate-onboarding.json',false,null,0,65537);$d=is_string($raw)&&strlen($raw)<=65536?json_decode($raw,true):null;
    if(!is_array($d)||($d['schema']??null)!==1||!is_string($d['listen_ip']??null)||!filter_var($d['listen_ip'],FILTER_VALIDATE_IP)||!is_array($d['allowed_ips']??null)||count($d['allowed_ips'])>32)return ['fresh'=>false];
    $ips=[];foreach($d['allowed_ips'] as $ip)if(is_string($ip)&&filter_var($ip,FILTER_VALIDATE_IP))$ips[]=$ip;
    $age=time()-(strtotime(($d['updated_at']??'').' UTC')?:0);
    return ['listen_ip'=>$d['listen_ip'],'port'=>5514,'allowed_ips'=>$ips,'fresh'=>$age>=-30&&$age<=90,'updated_at'=>$d['updated_at']??null];
}
