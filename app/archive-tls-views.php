<?php
declare(strict_types=1);
require_once __DIR__.'/archive-tls-history.php';
const ARCHIVE_TLS_VIEWS_LIMIT=20;
final class ArchiveTlsViewConflict extends RuntimeException {
 public function __construct(string $message,public int $status=409){parent::__construct($message);}
}
function archive_tls_view_config(mixed $json): array {
 if(!is_string($json)||strlen($json)>2048)throw new ManagementError('İnceleme filtreleri geçersiz.');
 try{$value=json_decode($json,false,8,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new ManagementError('İnceleme filtreleri okunamadı.');}
 $keys=['target','status','severity','from','to'];
 if(!$value instanceof stdClass||count(get_object_vars($value))!==count($keys)||array_diff(array_keys(get_object_vars($value)),$keys)||!is_int($value->target)||$value->target<0||$value->target>4294967295)throw new ManagementError('İnceleme filtreleri eksik veya geçersiz.');
 $input=[];foreach($keys as $key)$input['tls_history_'.$key]=$key==='target'?(string)$value->$key:$value->$key;
 $config=archive_tls_history_filters($input);unset($config['page']);return $config;
}
function archive_tls_view_target_available(int $target): bool {
 return $target===0||query("SELECT id FROM archive_destinations WHERE id=? AND protocol='ftps' UNION ALL SELECT destination_id FROM archive_tls_alert_history WHERE destination_id=? LIMIT 1",[$target,$target])!==[];
}
function archive_tls_view_row(array $row): array {
 $row['id']=(int)$row['id'];$row['revision']=(int)$row['revision'];$row['configuration']=archive_tls_view_config($row['configuration']);return $row;
}
function archive_tls_views_snapshot(int $uid): array {
 $rows=array_map('archive_tls_view_row',query('SELECT id,name,configuration,revision,created_at,updated_at FROM user_archive_tls_views WHERE user_id=? ORDER BY name,id',[$uid]));
 if(!$rows)return ['views'=>[],'limit'=>ARCHIVE_TLS_VIEWS_LIMIT];
 $known=[0=>true];foreach(query("SELECT id FROM archive_destinations WHERE protocol='ftps' UNION SELECT destination_id FROM archive_tls_alert_history") as $target)$known[(int)$target['id']]=true;
 foreach($rows as &$row)$row['target_available']=isset($known[$row['configuration']['target']]);unset($row);
 return ['views'=>$rows,'limit'=>ARCHIVE_TLS_VIEWS_LIMIT];
}
function archive_tls_view_read(int $uid,int $id,bool $lock=false): ?array {
 $row=query('SELECT id,name,configuration,revision,created_at,updated_at FROM user_archive_tls_views WHERE user_id=? AND id=?'.($lock?' FOR UPDATE':''),[$uid,$id])[0]??null;
 return $row?archive_tls_view_row($row):null;
}
function archive_tls_view_open(int $uid,array $input): array {
 $view=archive_tls_view_read($uid,management_int($input,'tls_view_id',1,4294967295));
 if(!$view)throw new ArchiveTlsViewConflict('Kayıtlı inceleme bulunamadı. Listeyi yenileyin.',404);
 if(!archive_tls_view_target_available($view['configuration']['target']))throw new ManagementError('Bu incelemenin hedefi artık bulunamıyor. Farklı bir hedef seçerek kaydı güncelleyin.',409);
 return ['view'=>$view];
}
function archive_tls_view_write(int $uid,array $input,bool $delete=false): array {
 $id=isset($input['id'])?management_int($input,'id',1,4294967295):null;
 if($delete&&$id===null)throw new ManagementError('Silinecek incelemeyi seçin.');
 $revision=$id===null?null:management_int($input,'revision',1,4294967295);
 if(!$delete){$name=management_text($input,'name',80);$config=archive_tls_view_config($input['configuration']??null);}
 $pdo=db();$pdo->beginTransaction();
 try {
  // One owner lock serializes limit/name checks and revalidates current rights.
  $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$uid])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  $old=$id===null?null:archive_tls_view_read($uid,$id,true);
  if($id!==null&&!$old)throw new ArchiveTlsViewConflict('Kayıtlı inceleme bulunamadı. Listeyi yenileyin.',404);
  if($old&&$old['revision']!==$revision)throw new ArchiveTlsViewConflict('Bu inceleme başka bir oturumda değişti. Güncel kaydı yükleyip yeniden deneyin.');
  $changed=true;
  if($delete)execute('DELETE FROM user_archive_tls_views WHERE user_id=? AND id=?',[$uid,$id]);
  else {
   if(!archive_tls_view_target_available($config['target']))throw new ManagementError('Seçili FTPS hedefi bulunamıyor. Başka bir hedef seçin.',409);
   if(query('SELECT id FROM user_archive_tls_views WHERE user_id=? AND name=? AND id<>?',[$uid,$name,$id??0]))throw new ManagementError('Bu adla bir incelemeniz var. Farklı ad seçin veya mevcut kaydı güncelleyin.',409);
   $encoded=json_encode($config,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
   if($old&&$old['name']===$name&&$old['configuration']===$config)$changed=false;
   elseif($old)execute('UPDATE user_archive_tls_views SET name=?,configuration=?,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE user_id=? AND id=?',[$name,$encoded,$uid,$id]);
   else {
    if((int)query('SELECT COUNT(*) n FROM user_archive_tls_views WHERE user_id=?',[$uid])[0]['n']>=ARCHIVE_TLS_VIEWS_LIMIT)throw new ManagementError('Hesabınızda en fazla 20 FTPS incelemesi saklayabilirsiniz.');
    execute('INSERT INTO user_archive_tls_views(user_id,name,configuration,created_at,updated_at) VALUES(?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))',[$uid,$name,$encoded]);$id=(int)$pdo->lastInsertId();
   }
  }
  $view=$delete?null:archive_tls_view_read($uid,$id);$result=['changed'=>$changed,'view'=>$view]+archive_tls_views_snapshot($uid);$pdo->commit();return $result;
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
