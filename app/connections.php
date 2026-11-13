<?php
declare(strict_types=1);
final class FortigateAccessError extends RuntimeException {}
function fg_worker_context(): bool {return !function_exists('query')||(PHP_SAPI==='cli'&&defined('FLS_CLI_WORKER')&&FLS_CLI_WORKER===true);}
function fg_connections(): array {
    static $rows;
    if($rows!==null)return $rows;
    // Standalone projection tests do not load the application database helpers.
    if(fg_worker_context())return [['id'=>0,'name'=>'FortiGate (legacy)','serial'=>FG_SERIAL,'vdom'=>'root','enabled'=>1,'is_default'=>1,'legacy_cache'=>1,'active_keys'=>1]];
    return $rows=query('SELECT id,name,serial,vdom,enabled,is_default,legacy_cache,(SELECT COUNT(*) FROM fortigate_credentials k WHERE k.connection_id=c.id AND k.enabled=1) active_keys FROM fortigate_connections c JOIN user_fortigate_access a ON a.connection_id=c.id AND a.user_id=? ORDER BY is_default DESC,c.id',[(int)($_SESSION['uid']??0)]);
}
function fg_account_device_id(): string {
    if(!isset($_SESSION['uid'])||!function_exists('query')||(PHP_SAPI==='cli'&&defined('FLS_CLI_WORKER')&&FLS_CLI_WORKER===true))return '';
    static $id;
    return $id??=(string)(query('SELECT connection_id FROM user_fortigate_preferences WHERE user_id=?',[(int)$_SESSION['uid']])[0]['connection_id']??'');
}
function fg_selected_device(): array {
    if(isset($GLOBALS['FLS_FG_CONTEXT'])){fg_authorize_device($GLOBALS['FLS_FG_CONTEXT']);return $GLOBALS['FLS_FG_CONTEXT'];}
    $id=$_GET['fg_device']??'';
    if(!is_string($id)||($id!==''&&!preg_match('/^[1-9][0-9]{0,9}$/D',$id)))throw new InvalidArgumentException('FortiGate geçersiz.');
    $devices=fg_connections();
    if($id!==''){foreach($devices as $row)if((string)$row['id']===$id)return $row;throw new FortigateAccessError('Bu FortiGate için erişim izniniz yok.');}
    return fg_default_device($devices);
}
function fg_default_device(?array $devices=null): array {
    $devices??=fg_connections();$saved=fg_account_device_id();
    foreach($devices as $row)if((string)$row['id']===$saved)return $row;
    foreach($devices as $row)if($row['is_default'])return $row;
    if($devices)return $devices[0];
    return ['id'=>0,'name'=>'FortiGate erişimi atanmamış','serial'=>'','vdom'=>'root','enabled'=>0,'legacy_cache'=>0,'active_keys'=>0];
}
function fg_authorize_device(array $device): void {
    if(fg_worker_context())return;
    foreach(fg_connections() as $d)if((int)$d['id']===(int)$device['id']&&$d['serial']===$device['serial']&&$d['vdom']===$device['vdom'])return;
    throw new FortigateAccessError('Bu FortiGate için erişim izniniz yok.');
}
function fg_require_access(): void {fg_authorize_device(fg_selected_device());}
function fg_serial(): string {return fg_selected_device()['serial'];}
function fg_vdom(): string {return fg_selected_device()['vdom'];}
function fg_root(?array $device=null): string {$d=$device??fg_selected_device();return FG_CACHE_ROOT.(!empty($d['legacy_cache'])?'':'/devices/'.(int)$d['id']);}
function fg_event_device(array $event): array {
    foreach(fg_connections() as $d)if($d['serial']===($event['devid']??'')&&$d['vdom']===($event['vd']??''))return $d;
    if(!fg_worker_context())throw new FortigateAccessError('Bu FortiGate için erişim izniniz yok.');
    return ['id'=>0,'name'=>'Bağlı değil','serial'=>$event['devid']??'','vdom'=>$event['vd']??'','enabled'=>0,'legacy_cache'=>0,'active_keys'=>0];
}
function fg_with_device(array $device,callable $work): mixed {
    fg_authorize_device($device);
    $before=$GLOBALS['FLS_FG_CONTEXT']??null;$GLOBALS['FLS_FG_CONTEXT']=$device;
    try{return $work();}finally{if($before===null)unset($GLOBALS['FLS_FG_CONTEXT']);else $GLOBALS['FLS_FG_CONTEXT']=$before;}
}
function fg_with_event(array $event,callable $work): mixed {return fg_with_device(fg_event_device($event),$work);}

/** Every report has one registered device, even when no URL filter was supplied. */
function fg_event_scope(string $alias='e'): string {
    $d=fg_selected_device();
    if($d['serial']==='')return '0';
    $serial=db()->quote($d['serial']);$vdom=db()->quote($d['vdom']);
    return "$alias.devid=$serial AND $alias.vd=$vdom AND BINARY $alias.devid=BINARY $serial AND BINARY $alias.vd=BINARY $vdom";
}
function fg_identity_scope(string $alias): string {
    return strtr(fg_event_scope('identity'),[
        'identity.devid'=>"JSON_UNQUOTE(JSON_EXTRACT($alias.identity_json,'$.devid'))",
        'identity.vd'=>"JSON_UNQUOTE(JSON_EXTRACT($alias.identity_json,'$.vd'))"]);
}
function fg_scoped_table(string $table): string {
    if(!in_array($table,['device_policies','device_sources','device_hourly_counts'],true))throw new LogicException('Unsupported device table');
    return '(SELECT * FROM '.$table.' metadata WHERE '.fg_event_scope('metadata').')';
}
function fg_require_event(int $id): void {
    if(!query('SELECT e.id FROM events e WHERE e.id=? AND '.fg_event_scope('e'),[$id]))throw new InvalidArgumentException('Kayıt seçili FortiGate üzerinde bulunamadı.');
}
