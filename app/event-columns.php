<?php
declare(strict_types=1);
const EVENT_COLUMNS=['time','outcome','source','target','policy','reason'];
function event_columns_validate(mixed $columns): array {
    if(!is_array($columns)||!array_is_list($columns)||count($columns)<1||count($columns)>count(EVENT_COLUMNS))throw new InvalidArgumentException('En az bir bilgi sütunu seçin.');
    foreach($columns as $column)if(!is_string($column)||!in_array($column,EVENT_COLUMNS,true))throw new InvalidArgumentException('Geçerli bilgi sütunlarını seçin.');
    if(count(array_unique($columns))!==count($columns))throw new InvalidArgumentException('Her sütunu yalnız bir kez seçin.');
    return array_values(array_intersect(EVENT_COLUMNS,$columns));
}
function event_columns_order(mixed $order): array {
    if(!is_array($order)||!array_is_list($order)||count($order)!==count(EVENT_COLUMNS))throw new InvalidArgumentException('Sütun sırası altı bilgi sütununu birer kez içermeli.');
    foreach($order as $key)if(!is_string($key)||!in_array($key,EVENT_COLUMNS,true))throw new InvalidArgumentException('Geçerli sütun sırasını gönderin.');
    if(count(array_unique($order))!==count(EVENT_COLUMNS))throw new InvalidArgumentException('Sütun sırasında tekrar olamaz.');
    return $order;
}
function event_columns_widths(mixed $json): array {
    if(!is_string($json)||strlen($json)>4096)throw new InvalidArgumentException('Geçerli sütun genişliklerini gönderin.');
    try{$object=json_decode($json,false,32,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new InvalidArgumentException('Geçerli sütun genişliklerini gönderin.');}
    if(!$object instanceof stdClass)throw new InvalidArgumentException('Genişlikler sütun adlarına göre belirtilmeli.');
    foreach($object as $key=>$width)if(!in_array($key,EVENT_COLUMNS,true)||!is_int($width)||$width<80||$width>1200)throw new InvalidArgumentException('Bilgi sütunu genişliği 80–1.200 tam piksel olmalı.');
    $widths=[];foreach(EVENT_COLUMNS as $key)if(property_exists($object,$key))$widths[$key]=$object->$key;
    return $widths;
}
function event_columns_pinned(mixed $json): array {
    if(!is_string($json)||strlen($json)>512)throw new InvalidArgumentException('Geçerli sabit sütunları gönderin.');
    try{$columns=json_decode($json,false,16,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new InvalidArgumentException('Geçerli sabit sütunları gönderin.');}
    if(!is_array($columns)||count($columns)>count(EVENT_COLUMNS))throw new InvalidArgumentException('Sabit sütunlar bir liste olmalı.');
    foreach($columns as $key)if(!is_string($key)||!in_array($key,EVENT_COLUMNS,true))throw new InvalidArgumentException('Geçerli bilgi sütunlarını sabitleyin.');
    if(count(array_unique($columns))!==count($columns))throw new InvalidArgumentException('Her sütunu yalnız bir kez sabitleyin.');
    return array_values(array_intersect(EVENT_COLUMNS,$columns));
}
function event_columns_read(int $userId): array {
    $row=query('SELECT visible_columns,column_order,column_widths,pinned_columns,revision,updated_at FROM user_event_columns WHERE user_id=?',[$userId])[0]??null;
    if(!$row)return ['columns'=>EVENT_COLUMNS,'order'=>EVENT_COLUMNS,'widths'=>(object)[],'pinned'=>[],'revision'=>0,'updated_at'=>null];
    return ['columns'=>event_columns_validate(json_decode($row['visible_columns'],true,512,JSON_THROW_ON_ERROR)),
        'order'=>$row['column_order']===null?EVENT_COLUMNS:event_columns_order(json_decode($row['column_order'],true,512,JSON_THROW_ON_ERROR)),
        'widths'=>(object)($row['column_widths']===null?[]:event_columns_widths($row['column_widths'])),
        'pinned'=>$row['pinned_columns']===null?[]:event_columns_pinned($row['pinned_columns']),
        'revision'=>(int)$row['revision'],'updated_at'=>$row['updated_at']];
}
function event_columns_save(int $userId,array $input): array {
    $columns=event_columns_validate($input['columns']??null);$version=$input['revision']??null;
    if(!is_string($version)||!preg_match('/^(0|[1-9][0-9]{0,17})$/D',$version))throw new InvalidArgumentException('Geçerli bir tercih sürümü gönderin.');
    $order=array_key_exists('order',$input)?event_columns_order($input['order']):null;
    $widths=array_key_exists('widths',$input)?event_columns_widths($input['widths']):null;
    $pinned=array_key_exists('pinned',$input)?event_columns_pinned($input['pinned']):null;
    $revision=(int)$version;$pdo=db();$pdo->beginTransaction();
    try{
        if(!query('SELECT id FROM users WHERE id=? FOR UPDATE',[$userId]))throw new RuntimeException('Preference account unavailable');
        $old=event_columns_read($userId);$order??=$old['order'];$widths??=(array)$old['widths'];$pinned??=$old['pinned'];
        if($old['revision']!==$revision){$pdo->rollBack();return ['http_status'=>409,'error'=>'Sütun tercihiniz başka bir oturumda değişti. Güncel seçimi yükleyip yeniden deneyin.']+$old;}
        if($old['columns']===$columns&&$old['order']===$order&&(array)$old['widths']===$widths&&$old['pinned']===$pinned){$pdo->commit();return ['changed'=>false]+$old;}
        $values=[json_encode($columns,JSON_THROW_ON_ERROR),json_encode($order,JSON_THROW_ON_ERROR),json_encode((object)$widths,JSON_THROW_ON_ERROR),json_encode($pinned,JSON_THROW_ON_ERROR),$userId];
        if($old['revision']===0)execute('INSERT INTO user_event_columns(visible_columns,column_order,column_widths,pinned_columns,user_id,revision,updated_at) VALUES(?,?,?,?,?,1,UTC_TIMESTAMP(6))',$values);
        else execute('UPDATE user_event_columns SET visible_columns=?,column_order=?,column_widths=?,pinned_columns=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE user_id=?',$values);
        $saved=event_columns_read($userId);$pdo->commit();return ['changed'=>true]+$saved;
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
