<?php
declare(strict_types=1);
require_once __DIR__.'/event-columns.php';
const EVENT_VIEWS_LIMIT=20;
const EVENT_VIEW_FILTERS=['target_key','target_label','source_reason','source_reason_label','outcome','policy','profile','module','source','reason','block_reason','block_reason_label','profile_missing','source_missing','policy_scope','q_field','q'];
function event_view_keys(mixed $value,array $keys): stdClass {
    if(!$value instanceof stdClass||count(get_object_vars($value))!==count($keys)||array_diff(array_keys(get_object_vars($value)),$keys))throw new InvalidArgumentException('Görünüm alanları eksik veya geçersiz.');
    return $value;
}
function event_view_text(mixed $value,int $limit): string {
    if(!is_string($value)||!mb_check_encoding($value,'UTF-8')||mb_strlen($value)>$limit||preg_match('/[\x00-\x1f\x7f]/u',$value))throw new InvalidArgumentException('Görünüm alanlarından biri geçersiz veya fazla uzun.');
    return $value;
}
function event_view_date(mixed $value): string {
    if(!is_string($value)||!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d{1,6})?)?(?:Z|[+-]\d\d:\d\d)?$/D',$value))throw new InvalidArgumentException('Özel aralık için geçerli bir tarih girin.');
    try{$date=new DateTimeImmutable($value,new DateTimeZone('Europe/Istanbul'));$errors=DateTimeImmutable::getLastErrors();if($errors&&($errors['warning_count']||$errors['error_count']))throw new Exception();return $date->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');}
    catch(Exception $e){throw new InvalidArgumentException('Özel aralık tarihi geçersiz.');}
}
function event_view_config(mixed $json): array {
    if(!is_string($json)||strlen($json)>32768)throw new InvalidArgumentException('Görünüm verisi geçersiz veya fazla uzun.');
    try{$c=json_decode($json,false,32,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new InvalidArgumentException('Görünüm verisi okunamadı.');}
    event_view_keys($c,['version','period','from','to','group_av','group_security','group_traffic','filters','layout']);
    if($c->version!==1||!in_array($c->period,['today','hour','24h','7d','fast','all','custom'],true))throw new InvalidArgumentException('Görünüm sürümü veya zaman aralığı geçersiz.');
    foreach(['group_av','group_security','group_traffic'] as $key)if(!is_bool($c->$key))throw new InvalidArgumentException('Gruplama seçimleri geçersiz.');
    if(!is_string($c->from)||!is_string($c->to))throw new InvalidArgumentException('Görünüm tarihleri geçersiz.');
    $from=$to='';if($c->period==='custom'){$from=event_view_date($c->from);$to=$c->to===''?'':event_view_date($c->to);if($to!==''&&$from>=$to)throw new InvalidArgumentException('Başlangıç, bitişten önce olmalı.');}
    elseif($c->from!==''||$c->to!=='')throw new InvalidArgumentException('Hareketli aralıkta sabit tarihler gönderilmemeli.');
    $legacySearch=($c->filters??null) instanceof stdClass&&!property_exists($c->filters,'q_field');
    if($legacySearch)$c->filters->q_field='';
    event_view_keys($c->filters,EVENT_VIEW_FILTERS);$filters=[];
    foreach(EVENT_VIEW_FILTERS as $key)$filters[$key]=event_view_text($c->filters->$key,match($key){'q'=>160,'profile'=>640,'target_label','source_reason_label','block_reason_label'=>1024,default=>512});
    if(!in_array($filters['q_field'],['','mail','sender','recipient','filename','message_id'],true))throw new InvalidArgumentException('Arama alanı geçersiz.');
    if(!in_array($filters['outcome'],['','all_blocks','security_block','rating_error','local_deny','policy_deny','observed','other_deny'],true)||!in_array($filters['policy_scope'],['','local','forward'],true))throw new InvalidArgumentException('Sonuç veya policy kapsamı geçersiz.');
    foreach(['profile_missing','source_missing'] as $key)if(!in_array($filters[$key],['','1'],true))throw new InvalidArgumentException('Eksik alan seçimi geçersiz.');
    foreach(['target_key','source_reason'] as $key)if($filters[$key]!==''&&!preg_match('/^[a-f0-9]{64}$/D',$filters[$key]))throw new InvalidArgumentException('Hedef veya gerekçe kimliği geçersiz.');
    if($filters['block_reason']!==''&&!preg_match('/^[sta]:[a-f0-9]{64}$/D',$filters['block_reason']))throw new InvalidArgumentException('Engelleme gerekçesi kimliği geçersiz.');
    if($filters['policy']!==''&&!preg_match('/^(?:-1|[0-9]{1,10})$/D',$filters['policy']))throw new InvalidArgumentException('Policy kimliği geçersiz.');
    if($filters['source']!==''&&!filter_var($filters['source'],FILTER_VALIDATE_IP))throw new InvalidArgumentException('Kaynak IP geçersiz.');
    foreach(['reason','module'] as $key)if(!preg_match('/^[a-zA-Z0-9_-]{0,64}$/D',$filters[$key]))throw new InvalidArgumentException('Gerekçe veya modül geçersiz.');
    if($legacySearch)unset($filters['q_field']);
    event_view_keys($c->layout,['columns','order','widths','pinned']);
    $layout=['columns'=>event_columns_validate($c->layout->columns),'order'=>event_columns_order($c->layout->order),
        'widths'=>(object)event_columns_widths(json_encode($c->layout->widths,JSON_THROW_ON_ERROR)),
        'pinned'=>event_columns_pinned(json_encode($c->layout->pinned,JSON_THROW_ON_ERROR))];
    return ['version'=>1,'period'=>$c->period,'from'=>$from,'to'=>$to,'group_av'=>$c->group_av,'group_security'=>$c->group_security,'group_traffic'=>$c->group_traffic,'filters'=>$filters,'layout'=>$layout];
}
function event_view_number(mixed $value,bool $zero=false): int {
    if(!is_string($value)||!preg_match($zero?'/^(0|[1-9][0-9]{0,17})$/D':'/^[1-9][0-9]{0,17}$/D',$value))throw new InvalidArgumentException('Görünüm kimliği veya sürümü geçersiz.');
    return (int)$value;
}
function event_view_row(array $row): array {
    return ['id'=>(int)$row['id'],'name'=>$row['name'],'sort_order'=>$row['sort_order']===null?null:(int)$row['sort_order'],'is_default'=>($row['is_default']??null)!==null,'configuration'=>event_view_config($row['configuration']),'revision'=>(int)$row['revision'],'created_at'=>$row['created_at'],'updated_at'=>$row['updated_at']];
}
function event_views_list(int $uid): array {return array_map('event_view_row',query('SELECT id,name,sort_order,is_default,configuration,revision,created_at,updated_at FROM user_event_views WHERE user_id=? ORDER BY sort_order IS NULL,sort_order,id',[$uid]));}
function event_view_read(int $uid,int $id): ?array {
    $row=query('SELECT id,name,sort_order,is_default,configuration,revision,created_at,updated_at FROM user_event_views WHERE user_id=? AND id=?',[$uid,$id])[0]??null;
    return $row?event_view_row($row):null;
}
function event_view_missing(): array {return ['http_status'=>404,'code'=>'not_found','error'=>'Görünüm bulunamadı. Güncel listeyi yükleyin.'];}
function event_view_conflict(array $view): array {return ['http_status'=>409,'code'=>'view_conflict','error'=>'Görünüm başka bir oturumda değişti. Güncel listeyi yükleyip yeniden deneyin.','view'=>$view];}
function event_view_write(int $uid,array $input,bool $delete=false): array {
    $id=isset($input['id'])?event_view_number($input['id']):null;
    if($delete&&$id===null)throw new InvalidArgumentException('Silinecek görünümü seçin.');
    $revision=$id===null?null:event_view_number($input['revision']??null);
    if(!$delete){$name=trim(event_view_text($input['name']??null,80));if($name==='')throw new InvalidArgumentException('Görünüme bir ad verin.');$config=event_view_config($input['configuration']??null);}
    $pdo=db();$pdo->beginTransaction();
    try{
        if(!query('SELECT id FROM users WHERE id=? FOR UPDATE',[$uid]))throw new RuntimeException('View account unavailable');
        $old=$id===null?null:event_view_read($uid,$id);
        if($id!==null&&!$old){$pdo->rollBack();return event_view_missing();}
        if($old&&$old['revision']!==$revision){$pdo->rollBack();return event_view_conflict($old);}
        $changed=true;
        if($delete)execute('DELETE FROM user_event_views WHERE user_id=? AND id=?',[$uid,$id]);
        else{
            if(query('SELECT id FROM user_event_views WHERE user_id=? AND name=? AND id<>?',[$uid,$name,$id??0])){$pdo->rollBack();return ['http_status'=>409,'code'=>'name_exists','error'=>'Bu adla bir görünümünüz var. Farklı ad seçin veya mevcut görünümü güncelleyin.'];}
            $encoded=json_encode($config,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
            if($old&&$old['name']===$name&&json_encode($old['configuration'],JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE)===$encoded)$changed=false;
            elseif($old)execute('UPDATE user_event_views SET name=?,configuration=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE user_id=? AND id=?',[$name,$encoded,$uid,$id]);
            else{
                if((int)(query('SELECT COUNT(*) n FROM user_event_views WHERE user_id=?',[$uid])[0]['n'])>=EVENT_VIEWS_LIMIT){$pdo->rollBack();return ['http_status'=>422,'error'=>'Hesabınızda en fazla '.EVENT_VIEWS_LIMIT.' görünüm saklayabilirsiniz.'];}
                execute('INSERT INTO user_event_views(user_id,name,configuration,revision,created_at,updated_at) VALUES(?,?,?,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))',[$uid,$name,$encoded]);$id=(int)$pdo->lastInsertId();
            }
        }
        $view=$delete?null:event_view_read($uid,$id);$views=event_views_list($uid);$pdo->commit();return ['changed'=>$changed,'view'=>$view]+event_views_snapshot($views);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
function event_view_apply(int $uid,array $input): array {
    $id=event_view_number($input['id']??null);$revision=event_view_number($input['revision']??null);$columnsRevision=event_view_number($input['columns_revision']??null,true);
    $view=event_view_read($uid,$id);if(!$view)return event_view_missing();if($view['revision']!==$revision)return event_view_conflict($view);
    $layout=$view['configuration']['layout'];$preferences=event_columns_save($uid,['columns'=>$layout['columns'],'order'=>$layout['order'],'widths'=>json_encode($layout['widths'],JSON_THROW_ON_ERROR),'pinned'=>json_encode($layout['pinned'],JSON_THROW_ON_ERROR),'revision'=>(string)$columnsRevision]);
    if(isset($preferences['http_status']))return ['code'=>'column_conflict']+$preferences;
    return ['view'=>$view,'preferences'=>$preferences];
}

/** A nullable unique account/marker key allows many ordinary views and one default. */
function event_view_default(int $uid,array $input): array {
    $id=event_view_number($input['id']??null,true);$revision=event_view_number($input['revision']??null,true);
    $previous=event_view_number($input['previous_id']??null,true);$previousRevision=event_view_number($input['previous_revision']??null,true);
    if(($id===0)!==($revision===0)||($previous===0)!==($previousRevision===0))throw new InvalidArgumentException('Varsayılan görünüm sürümünü yeniden yükleyin.');
    $pdo=db();$pdo->beginTransaction();
    try{
        if(!query('SELECT id FROM users WHERE id=? FOR UPDATE',[$uid]))throw new RuntimeException('Default view account unavailable');
        $target=$id===0?null:event_view_read($uid,$id);
        if($id!==0&&!$target){$pdo->rollBack();return event_view_missing();}
        if($target&&$target['revision']!==$revision){$pdo->rollBack();return event_view_conflict($target);}
        $current=query('SELECT id,revision FROM user_event_views WHERE user_id=? AND is_default=1',[$uid])[0]??null;
        if(($current?(int)$current['id']:0)!==$previous||($current?(int)$current['revision']:0)!==$previousRevision){$pdo->rollBack();return ['http_status'=>409,'code'=>'default_conflict','error'=>'Varsayılan seçimi başka bir oturumda değişti. Güncel listeyi yükleyip yeniden deneyin.'];}
        $changed=($current?(int)$current['id']:0)!==$id;
        if($changed){
            if($current)execute('UPDATE user_event_views SET is_default=NULL,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE user_id=? AND id=?',[$uid,$current['id']]);
            if($target)execute('UPDATE user_event_views SET is_default=1,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE user_id=? AND id=?',[$uid,$id]);
        }
        $views=event_views_list($uid);$pdo->commit();return ['changed'=>$changed]+event_views_snapshot($views);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}

/** The token covers membership, saved-view revisions and the complete observed order. */
function event_views_order_token(array $views): string {
    return hash('sha256',json_encode(array_map(fn($v)=>[$v['id'],$v['revision'],$v['sort_order']],$views),JSON_THROW_ON_ERROR));
}
function event_views_snapshot(array $views): array {return ['views'=>$views,'order_token'=>event_views_order_token($views)];}
function event_views_reorder(int $uid,array $input): array {
    $token=$input['snapshot']??null;$json=$input['order']??null;
    if(!is_string($token)||!preg_match('/^[a-f0-9]{64}$/D',$token)||!is_string($json)||strlen($json)>2048)throw new InvalidArgumentException('Görünüm sırasını yeniden yükleyin.');
    try{$order=json_decode($json,false,16,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new InvalidArgumentException('Görünüm sırası geçersiz.');}
    if(!is_array($order)||count($order)>EVENT_VIEWS_LIMIT)throw new InvalidArgumentException('Görünüm sırası bir liste olmalı.');
    $ids=array_map(fn($id)=>event_view_number($id),$order);
    if(count(array_unique($ids))!==count($ids))throw new InvalidArgumentException('Her görünümü yalnız bir kez sıralayın.');
    $pdo=db();$pdo->beginTransaction();
    try{
        if(!query('SELECT id FROM users WHERE id=? FOR UPDATE',[$uid]))throw new RuntimeException('View order account unavailable');
        $views=event_views_list($uid);
        if(!hash_equals(event_views_order_token($views),$token)){$pdo->rollBack();return ['http_status'=>409,'code'=>'order_conflict','error'=>'Görünüm listesi başka bir oturumda değişti. Güncel listeyi yükleyip yeniden sıralayın.'];}
        $owned=array_column($views,'id');$expected=$owned;$given=$ids;sort($expected);sort($given);
        if($expected!==$given)throw new InvalidArgumentException('Sıra, hesabınızdaki tüm görünümleri birer kez içermeli.');
        $changed=$owned!==$ids;
        if($changed){$positions=array_column($views,'sort_order','id');foreach($ids as $position=>$id)if($positions[$id]!==$position)execute('UPDATE user_event_views SET sort_order=? WHERE user_id=? AND id=?',[$position,$uid,$id]);}
        $views=event_views_list($uid);$pdo->commit();return ['changed'=>$changed]+event_views_snapshot($views);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
