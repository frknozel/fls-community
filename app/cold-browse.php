<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
const FLS_COLD_QUERY_SOCKET='/run/fls-cold-query.sock';
const FLS_COLD_BROWSE_RAW='/srv/fortigate/raw';
const FLS_COLD_QUERY_RESPONSE=4194304;
function cold_browse_scope(): array {fg_require_access();return fg_selected_device();}
function cold_browse_uint(mixed $value,string $field='Kimlik'): string {
    if(!is_string($value)||!preg_match('/^[1-9][0-9]{0,19}$/D',$value)||strlen($value)>20||(strlen($value)===20&&strcmp($value,'18446744073709551615')>0))throw new ManagementError($field.' geçersiz.');return $value;
}
function cold_browse_snapshot_id(mixed $value): string {
    $value=cold_browse_uint($value,'Kopya');$maximum=(string)PHP_INT_MAX;if(strlen($value)>strlen($maximum)||(strlen($value)===strlen($maximum)&&strcmp($value,$maximum)>0))throw new ManagementError('Kopya kimliği desteklenen aralığı aşıyor.');return $value;
}
function cold_browse_where(string $alias='d'): array {$d=cold_browse_scope();return ["BINARY $alias.devid=BINARY ? AND BINARY $alias.vd=BINARY ?",[$d['serial'],$d['vdom']]];}
function cold_browse_selection(string $id): array {
    [$where,$args]=cold_browse_where();$row=query("SELECT s.id,s.file_id,s.source_file,s.purpose,s.snapshot_at,s.verified_at,s.manifest_sha256,d.event_count,d.min_event_at,d.max_event_at FROM cold_snapshot_devices d JOIN cold_snapshots s ON s.id=d.snapshot_id AND BINARY s.manifest_sha256=BINARY d.manifest_sha256 WHERE $where AND s.id=? AND s.status='verified' AND s.restore_verified_at IS NOT NULL",[...$args,$id])[0]??null;
    if(!$row)throw new ManagementError('Kopya seçili cihaz için bulunamadı veya kapsamı hazırlanıyor.',404);$row['id']=(string)$row['id'];$row['file_id']=(string)$row['file_id'];$row['event_count']=(int)$row['event_count'];return $row;
}
function cold_browse_catalog(): array {
    [$where,$args]=cold_browse_where();$page=management_int(['page'=>$_GET['cold_catalog_page']??'1'],'page',1,100000);$limit=20;
    $from="FROM cold_snapshot_devices d JOIN cold_snapshots s ON s.id=d.snapshot_id AND BINARY s.manifest_sha256=BINARY d.manifest_sha256 WHERE $where AND s.status='verified' AND s.restore_verified_at IS NOT NULL";
    db()->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    try{
        $total=(int)query("SELECT COUNT(*) n $from",$args)[0]['n'];$pages=max(1,(int)ceil($total/$limit));$page=min($page,$pages);$offset=($page-1)*$limit;
        $rows=query("SELECT s.id,s.source_file,s.purpose,s.snapshot_at,s.verified_at,d.event_count,d.min_event_at,d.max_event_at $from ORDER BY s.id DESC LIMIT $limit OFFSET $offset",$args);
        $selected=null;if(($_GET['cold_snapshot']??'')!=='')$selected=cold_browse_selection(cold_browse_snapshot_id($_GET['cold_snapshot']));
        db()->commit();
    }catch(Throwable $e){if(db()->inTransaction())db()->rollBack();throw $e;}
    foreach($rows as &$row){$row['id']=(string)$row['id'];$row['event_count']=(int)$row['event_count'];}unset($row);$d=fg_selected_device();
    return ['device'=>['id'=>(int)$d['id'],'serial'=>$d['serial'],'vdom'=>$d['vdom']],'snapshots'=>$rows,'selected_snapshot'=>$selected,'pagination'=>['page'=>$page,'pages'=>$pages,'total'=>$total,'page_size'=>$limit],'coverage'=>'verified_only'];
}
function cold_browse_deadline($stream,int $deadline): void {
    $left=$deadline-hrtime(true);if($left<=0)throw new ManagementError('Arşiv sorgu servisi süre sınırına ulaştı.',503);stream_set_timeout($stream,intdiv($left,1000000000),max(1,(int)(($left%1000000000)/1000)));
}
function cold_browse_read($stream,int $bytes,int $deadline): string {
    $data='';while(strlen($data)<$bytes){$remaining=$bytes-strlen($data);cold_browse_deadline($stream,$deadline);$part=fread($stream,min(65536,$remaining));if($part===false||$part==='')throw new ManagementError('Arşiv sorgu servisi yanıt vermedi.',503);$data.=$part;}return $data;
}
function cold_browse_transport(array $message): array {
    $raw=json_encode($message,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);if(strlen($raw)>16384)throw new ManagementError('Sorgu boyutu sınırı aşıldı.');
    $deadline=hrtime(true)+3000000000;
    $socket=@stream_socket_client('unix://'.FLS_COLD_QUERY_SOCKET,$code,$error,1,STREAM_CLIENT_CONNECT);
    if(!$socket)throw new ManagementError('Arşiv sorgu servisine ulaşılamadı.',503);
    try{
        stream_set_timeout($socket,3);$frame=pack('N',strlen($raw)).$raw;$written=0;
        while($written<strlen($frame)){$remaining=substr($frame,$written);cold_browse_deadline($socket,$deadline);$n=fwrite($socket,$remaining);if($n===false||$n===0)throw new ManagementError('Arşiv sorgusu gönderilemedi.',503);$written+=$n;}
        $size=unpack('Nlength',cold_browse_read($socket,4,$deadline))['length'];if($size<2||$size>FLS_COLD_QUERY_RESPONSE)throw new ManagementError('Arşiv servis yanıtı geçersiz.',502);
        $data=json_decode(cold_browse_read($socket,$size,$deadline),true,64,JSON_THROW_ON_ERROR);
        if(!is_array($data)||!is_bool($data['ok']??null))throw new ManagementError('Arşiv servis yanıtı geçersiz.',502);
    }catch(ManagementError $e){throw $e;}catch(Throwable $e){throw new ManagementError('Arşiv servis yanıtı geçersiz.',502);}finally{fclose($socket);}
    return $data;
}
function cold_browse_error(string $code,int $status): never {
    $labels=['invalid_request'=>'Sorgu alanları geçersiz.','invalid_scope'=>'Cihaz kapsamı geçersiz.','invalid_filters'=>'Filtreler geçersiz.','invalid_cursor'=>'Sayfa bağlantısının kapsamı veya süresi değişti; sorguyu yeniden başlatın.','cursor_key'=>'Sayfa bağlantısı doğrulanamadı.','unauthenticated'=>'Oturum geçerliliğini yitirdi.','access_denied'=>'Bu cihaz için erişim izniniz yok.','event_not_found'=>'Kayıt seçili kopya ve cihazda bulunamadı.','job_not_found'=>'Sorgunun süresi doldu; yeniden başlatın.','queue_full'=>'Arşiv sorgu kuyruğu dolu; kısa süre sonra yeniden deneyin.','query_timeout'=>'Arşiv sorgusu süre sınırına ulaştı; filtreleri daraltın.','result_too_large'=>'Sonuç boyutu sınırı aşıldı; filtreleri daraltın.','snapshot_invalid'=>'Arşiv kopyasının doğrulaması tamamlanamadı.','catalog_mismatch'=>'Kopya ile katalog eşleşmiyor.','cache_unsafe'=>'Arşiv okuma alanı doğrulanamadı.','cache_changed'=>'Arşiv okuma kopyası değişti.','payload_changed'=>'Arşiv verisi değişti.','cache_budget'=>'Kopya, sorgu önbelleği alan sınırını aşıyor.','service_unavailable'=>'Arşiv sorgusu tamamlanamadı.'];
    if(!in_array($status,[400,401,403,404,409,413,422,429,503],true)||!isset($labels[$code]))throw new ManagementError('Arşiv sorgusu tamamlanamadı.',503);
    throw new ManagementError($labels[$code],$status);
}
function cold_browse_event(array $row,array $device,array $snapshot): void {
    if(($row['devid']??null)!==$device['serial']||($row['vd']??null)!==$device['vdom'])throw new ManagementError('Arşiv yanıtının cihaz kapsamı doğrulanamadı.',502);
    if(($row['file_id']??null)!==(string)$snapshot['file_id'])throw new ManagementError('Arşiv kaydının kaynak dosyası eşleşmiyor.',502);
    try{cold_browse_uint($row['id']??null);}catch(Throwable $e){throw new ManagementError('Arşiv kayıt kimliği geçersiz.',502);}
    foreach(['event_at','received_at'] as $key)if(!is_string($row[$key]??null)||!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$/D',$row[$key]))throw new ManagementError('Arşiv kayıt zamanı geçersiz.',502);
}
function cold_browse_raw(array $event,array $snapshot): array {
    $empty=['raw'=>null,'raw_verified'=>false,'raw_status'=>'unavailable'];$name=$snapshot['source_file'];
    if(!preg_match('/^\d{4}-\d{2}-\d{2}-\d{2}\.jsonl$/D',$name)||!preg_match('/^[a-f0-9]{64}$/D',$event['raw_sha256']??''))return $empty;
    foreach(['byte_offset','byte_length'] as $key)if(!is_string($event[$key]??null)||!preg_match('/^\d{1,10}$/D',$event[$key]))return $empty;
    $offset=(int)$event['byte_offset'];$length=(int)$event['byte_length'];if($length<1||$length>1048576)return $empty;
    $directory=@lstat(FLS_COLD_BROWSE_RAW);if(!$directory||($directory['mode']&0170000)!==0040000)return $empty;
    $path=FLS_COLD_BROWSE_RAW.'/'.$name;$stat=@lstat($path);if(!$stat||($stat['mode']&0170000)!==0100000||$stat['nlink']!==1||$offset+$length>$stat['size'])return $empty;
    $f=@fopen($path,'rb');if(!$f)return $empty;
    try{$open=fstat($f);if(!$open||$stat['dev']!==$open['dev']||$stat['ino']!==$open['ino']||fseek($f,$offset)!==0)return $empty;$line=fread($f,$length);if($line===false||strlen($line)!==$length||!str_ends_with($line,"\n"))return $empty;$data=json_decode($line,true,16,JSON_THROW_ON_ERROR);$raw=$data['raw']??null;if(!is_string($raw))return $empty;if(!hash_equals($event['raw_sha256'],hash('sha256',$raw)))return ['raw'=>null,'raw_verified'=>false,'raw_status'=>'mismatch'];return ['raw'=>$raw,'raw_verified'=>true,'raw_status'=>'verified'];}
    catch(Throwable $e){return $empty;}finally{fclose($f);}
}
function cold_browse_query(string $route): array {
    $device=cold_browse_scope();$request=['version'=>1,'op'=>$route==='cold_query_start'?'start':'status','actor'=>['user_id'=>(int)$_SESSION['uid'],'session_version'=>(int)$_SESSION['session_version']],'device_id'=>(int)$device['id']];
    if($route==='cold_query_start'){
        $token=$_POST['_csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??null;if(!is_string($token)||!hash_equals($_SESSION['csrf'],$token))throw new ManagementError('Oturum doğrulaması başarısız.',403);
        foreach($_POST as $key=>$value)if(!in_array($key,['snapshot_id','kind','from','to','source','target','q','module','outcome','cursor','event_id','_csrf'],true)||!is_string($value))throw new ManagementError('Sorgu alanları geçersiz.');
        $id=cold_browse_snapshot_id($_POST['snapshot_id']??null);cold_browse_selection($id);$kind=management_enum($_POST,'kind',['list','detail']);$filters=[];
        foreach(['from','to','source','target','q','module','outcome'] as $key)$filters[$key]=management_text($_POST,$key,$key==='q'?160:80,false);
        foreach(['from','to'] as $key)if($filters[$key]!==''){try{$filters[$key]=utc($filters[$key]);}catch(InvalidArgumentException $e){throw new ManagementError('Tarih filtresi geçersiz.');}}
        if($filters['from']!==''&&$filters['to']!==''&&$filters['from']>=$filters['to'])throw new ManagementError('Başlangıç bitişten önce olmalı.');
        foreach(['source','target'] as $key)if($filters[$key]!==''&&!filter_var($filters[$key],FILTER_VALIDATE_IP))throw new ManagementError('Kaynak ve hedef geçerli IP adresi olmalı.');
        if(!in_array($filters['module'],['','virus','webfilter','app-ctrl','dns','ips','ssl','forward','local','system','vpn','user','router','ha','connector','anomaly','voip','unknown'],true)||!in_array($filters['outcome'],['','security_block','policy_deny','local_deny','other_deny','rating_error','observed'],true))throw new ManagementError('Modül veya karar filtresi geçersiz.');
        $cursor=$_POST['cursor']??'';if(strlen($cursor)>4096||($cursor!==''&&!preg_match('/^[A-Za-z0-9_\-.=]+$/D',$cursor)))throw new ManagementError('Sayfa bağlantısı geçersiz.');
        $eventId=$kind==='detail'?cold_browse_uint($_POST['event_id']??null,'Olay'):null;
        $request+=['snapshot_id'=>(int)$id,'kind'=>$kind,'filters'=>$filters,'cursor'=>$cursor===''?null:$cursor,'event_id'=>$eventId];
    }else{$job=$_GET['job_id']??'';if(!is_string($job)||!preg_match('/^[a-f0-9]{32}$/D',$job))throw new ManagementError('Sorgu kimliği geçersiz.');$request['job_id']=$job;}
    $reply=cold_browse_transport($request);
    if(!$reply['ok']){if(!is_string($reply['code']??null)||!is_int($reply['status']??null))throw new ManagementError('Arşiv servis hatası geçersiz.',502);cold_browse_error($reply['code'],$reply['status']);}
    if(!is_string($reply['job_id']??null)||!preg_match('/^[a-f0-9]{32}$/D',$reply['job_id'])||($request['op']==='status'&&$reply['job_id']!==$request['job_id'])||!is_array($reply['device']??null)||count($reply['device'])!==3||($reply['device']['id']??null)!==(int)$device['id']||($reply['device']['serial']??null)!==$device['serial']||($reply['device']['vdom']??null)!==$device['vdom']||!is_int($reply['snapshot_id']??null)||!in_array($reply['kind']??null,['list','detail'],true)||!in_array($reply['status']??null,['queued','preparing','ready','error'],true))throw new ManagementError('Arşiv sorgu kapsamı doğrulanamadı.',502);
    if($request['op']==='start'&&($reply['snapshot_id']!==$request['snapshot_id']||$reply['kind']!==$request['kind']))throw new ManagementError('Arşiv sorgu kapsamı değişti.',502);
    if(!array_key_exists('event_id',$reply)||($reply['kind']==='list'&&$reply['event_id']!==null)||($reply['kind']==='detail'&&(!is_string($reply['event_id'])||!preg_match('/^[1-9][0-9]{0,19}$/D',$reply['event_id']))))throw new ManagementError('Arşiv olay kapsamı geçersiz.',502);
    if($reply['kind']==='detail'){try{cold_browse_uint($reply['event_id']);}catch(Throwable $e){throw new ManagementError('Arşiv olay kimliği geçersiz.',502);}}
    if($request['op']==='start'&&$reply['event_id']!==$request['event_id'])throw new ManagementError('Arşiv olay kapsamı değişti.',502);
    $snapshot=cold_browse_selection((string)$reply['snapshot_id']);$reply['snapshot']=$snapshot;
    if($reply['status']==='error'){if(!is_array($reply['error']??null)||!is_string($reply['error']['code']??null)||!is_int($reply['error']['status']??null))throw new ManagementError('Arşiv servis yanıtı geçersiz.',502);cold_browse_error($reply['error']['code']??'service_unavailable',$reply['error']['status']??503);}
    if($reply['status']==='ready'){
        $result=$reply['result']??null;if(!is_array($result)||($result['snapshot_id']??null)!==(string)$snapshot['id']||($result['manifest_sha256']??null)!==$snapshot['manifest_sha256'])throw new ManagementError('Arşiv sonucu katalogla eşleşmiyor.',502);
        if($reply['kind']==='list'){
            if(!is_array($result['rows']??null)||!array_is_list($result['rows'])||count($result['rows'])>50||!is_bool($result['has_more']??null)||!is_null($result['next_cursor']??null)&&!is_string($result['next_cursor']))throw new ManagementError('Arşiv sonuç biçimi geçersiz.',502);
            if(is_string($result['next_cursor']??null)&&(strlen($result['next_cursor'])>4096||!preg_match('/^[A-Za-z0-9_\-.=]+$/D',$result['next_cursor'])))throw new ManagementError('Arşiv sayfa bağlantısı geçersiz.',502);
            if($result['has_more']!==(is_string($result['next_cursor']??null)&&$result['next_cursor']!==''))throw new ManagementError('Arşiv sayfa bağlantısı eksik.',502);
            foreach($result['rows'] as $row){if(!is_array($row))throw new ManagementError('Arşiv kayıt biçimi geçersiz.',502);cold_browse_event($row,$device,$snapshot);}
        }else{
            if(!is_array($result['event']??null)||!is_string($result['fields_text']??null)||strlen($result['fields_text'])>1048576||!is_array($result['notes']??null)||count($result['notes'])>100)throw new ManagementError('Arşiv ayrıntı biçimi geçersiz.',502);
            cold_browse_event($result['event'],$device,$snapshot);if($result['event']['id']!==$reply['event_id'])throw new ManagementError('Arşiv olay kimliği eşleşmiyor.',502);foreach($result['notes'] as $note)if(!is_array($note)||($note['event_id']??null)!==$result['event']['id'])throw new ManagementError('Arşiv not kapsamı geçersiz.',502);
            try{$fields=json_decode($result['fields_text'],true,64,JSON_THROW_ON_ERROR);if(!is_array($fields))throw new RuntimeException();}catch(Throwable $e){throw new ManagementError('Arşiv alanları çözümlenemedi.',502);}
            $reply['result']['fields']=$fields;$reply['result']+=cold_browse_raw($result['event'],$snapshot);
        }
    }elseif(($reply['result']??null)!==null)throw new ManagementError('Hazırlanan arşiv sonucu geçersiz.',502);
    return $reply;
}
