<?php
declare(strict_types=1);
require_once __DIR__.'/recovery-download.php';

const BACKUP_ENCRYPTION_CONFIG='/etc/fls/backup-encryption.json';
const BACKUP_ENCRYPTION_EXPORT='/var/lib/fls-backup-key-download';

function backup_encryption_recipient(mixed $value): bool {return is_string($value)&&preg_match('/^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$/D',$value)===1;}
function backup_encryption_key_id(mixed $value): bool {return is_string($value)&&preg_match('/^[a-f0-9]{32}$/D',$value)===1;}
function backup_encryption_group(): int {
 $group=function_exists('posix_getgrnam')?posix_getgrnam('fls-web'):false;if(!$group)throw new RecoveryDownloadError(503);return (int)$group['gid'];
}
function backup_encryption_parent(string $path): void {
 $current='';foreach(explode('/',trim(dirname($path),'/')) as $part){
  if($part===''||$part==='.'||$part==='..')throw new RecoveryDownloadError(409);$current.='/'.$part;$info=@lstat($current);
  if(!$info||($info['mode']&0170000)!==0040000||$info['uid']!==0||(($info['mode']&0022)!==0&&($info['mode']&01000)===0))throw new RecoveryDownloadError(409);
 }
}
function backup_encryption_json(string $path,int $maximum=8192): array {
 backup_encryption_parent($path);$stream=recovery_download_open($path,backup_encryption_group(),$maximum);
 try{$before=fstat($stream);$text=stream_get_contents($stream);$after=fstat($stream);if(!is_string($text)||!$before||!$after||strlen($text)!==$before['size']||!recovery_download_same_stat($before,$after))throw new RecoveryDownloadError(409);$value=json_decode($text,true,16,JSON_THROW_ON_ERROR);if(!is_array($value)||array_is_list($value))throw new RecoveryDownloadError(409);return $value;}
 finally{fclose($stream);}
}
function backup_encryption_state(): array {
 $out=['schema'=>1,'status'=>'disabled','active'=>null,'pending'=>null,'error_code'=>''];
 try{
  if(@lstat(BACKUP_ENCRYPTION_CONFIG)!==false){
   $value=backup_encryption_json(BACKUP_ENCRYPTION_CONFIG,4096);
   if(count($value)!==5||($value['schema']??null)!==1||($value['custody_confirmed']??null)!==true||!backup_encryption_recipient($value['recipient']??null)||($value['key_id']??null)!==substr(hash('sha256',$value['recipient']),0,32)||!is_string($value['activated_at']??null)||!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/D',$value['activated_at']))throw new RecoveryDownloadError(409);
   $out['active']=$value;$out['status']='active';
  }
  if(@lstat(BACKUP_ENCRYPTION_EXPORT.'/pending.json')!==false){
   recovery_download_directory(BACKUP_ENCRYPTION_EXPORT);$value=backup_encryption_json(BACKUP_ENCRYPTION_EXPORT.'/pending.json',4096);
   if(($value['schema']??null)!==1||($value['self_test_verified']??null)!==true||!backup_encryption_recipient($value['recipient']??null)||($value['key_id']??null)!==substr(hash('sha256',$value['recipient']),0,32)||($value['download_filename']??null)!=='fls-backup-recovery-'.$value['key_id'].'.txt'||!is_string($value['created_at']??null)||!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/D',$value['created_at']))throw new RecoveryDownloadError(409);
   $stream=recovery_download_open(BACKUP_ENCRYPTION_EXPORT.'/'.$value['download_filename'],backup_encryption_group(),4096);fclose($stream);
   $out['pending']=['key_id'=>$value['key_id'],'recipient'=>$value['recipient'],'created_at'=>$value['created_at'],'self_test_verified'=>true,'download_url'=>'/api.php?route=backup_encryption_key&key_id='.$value['key_id']];
   if($out['active']===null)$out['status']='pending_custody';
  }
 }catch(Throwable $error){$out['status']='error';$out['error_code']='encryption_state_invalid';}
 return $out;
}
function backup_encryption_companion(array $backup,string $key): array {
 if(!backup_encryption_key_id($key)||!is_string($backup['filename']??null)||!preg_match('/^fls-system-\d{8}-\d{6}Z\.tar\.gz$/D',$backup['filename']))throw new RecoveryDownloadError(422);
 recovery_download_directory(SYSTEM_BACKUPS_DIRECTORY);$name=$backup['filename'].'.'.$key.'.age';$value=backup_encryption_json(SYSTEM_BACKUPS_DIRECTORY.'/'.$name.'.encryption.json');
 if(($value['schema']??null)!=='fls-backup-age-v1'||($value['algorithm']??null)!=='age-x25519'||($value['backup_id']??null)!==(int)$backup['id']||($value['source_filename']??null)!==$backup['filename']||($value['source_sha256']??null)!==$backup['sha256']||($value['source_bytes']??null)!==(int)$backup['bytes']||($value['filename']??null)!==$name||($value['key_id']??null)!==$key||!backup_encryption_recipient($value['recipient']??null)||substr(hash('sha256',$value['recipient']),0,32)!==$key||($value['custody_confirmed']??null)!==true||!is_int($value['bytes']??null)||$value['bytes']<1||!is_string($value['sha256']??null)||!preg_match('/^[a-f0-9]{64}$/D',$value['sha256']))throw new RecoveryDownloadError(409);
 $stream=recovery_download_open(SYSTEM_BACKUPS_DIRECTORY.'/'.$name,backup_encryption_group(),$value['bytes'],$value['bytes']);fclose($stream);
 return $value;
}
function backup_encryption_companions(array $backup): array {
 $out=[];foreach(array_slice(glob(SYSTEM_BACKUPS_DIRECTORY.'/'.$backup['filename'].'.*.age.encryption.json')?:[],0,32) as $path){
  $key=substr(basename($path),strlen($backup['filename'])+1,32);try{$value=backup_encryption_companion($backup,$key);}catch(Throwable $error){continue;}
  $url='/api.php?route=system_backup_file&id='.$backup['id'].'&key_id='.$key;
  $out[]=['key_id'=>$key,'filename'=>$value['filename'],'bytes'=>$value['bytes'],'sha256'=>$value['sha256'],'created_at'=>$value['created_at']??null,'download_url'=>$url.'&part=encrypted','checksum_url'=>$url.'&part=encrypted_sha256','report_url'=>$url.'&part=encryption_report'];
 }
 usort($out,fn($a,$b)=>strcmp((string)$b['created_at'],(string)$a['created_at']));return $out;
}
function backup_encryption_key_download(): never {
 system_backups_admin('GET');foreach($_GET as $key=>$value)if(!in_array($key,['route','key_id'],true)||!is_string($value))throw new ManagementError('Anahtar indirme isteği geçersiz.');
 $key=$_GET['key_id']??'';if(!backup_encryption_key_id($key))throw new ManagementError('Kurtarma anahtarı kimliği geçersiz.');$stream=null;
 try{
  $state=backup_encryption_state();if($state['status']==='error'||($state['pending']['key_id']??null)!==$key)throw new RecoveryDownloadError(404);
  $directory=recovery_download_directory(BACKUP_ENCRYPTION_EXPORT);$name='fls-backup-recovery-'.$key.'.txt';$stream=recovery_download_open(BACKUP_ENCRYPTION_EXPORT.'/'.$name,$directory['gid'],4096);
  $before=fstat($stream);$hash=hash_init('sha256');$read=hash_update_stream($hash,$stream);$sha=hash_final($hash);$after=fstat($stream);
  if(!$before||!$after||$read!==$before['size']||!recovery_download_same_stat($before,$after)||!rewind($stream))throw new RecoveryDownloadError(409);
  system_backups_admin('GET');audit('backup_recovery_identity_download','key_id='.$key);
  recovery_download_headers($name,'text/plain; charset=utf-8',$before['size'],$sha,$sha);
 }catch(RecoveryDownloadError $error){if(is_resource($stream))fclose($stream);throw new ManagementError('Kurtarma anahtarı şu anda indirilemiyor.',$error->status);}
 if(@fpassthru($stream)===false)error_log('FLS backup recovery key stream interrupted.');fclose($stream);exit;
}
