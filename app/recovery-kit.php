<?php
declare(strict_types=1);
require_once __DIR__.'/system-backups.php';

const RECOVERY_KIT_RUNTIME='/var/lib/fls-recovery-download/recovery-runtime';
const RECOVERY_KIT_MACHINE_ID='/etc/machine-id';
const RECOVERY_KIT_MAX_RUNTIME=4294967296;

/** Only this installed, root-owned code is admitted; no uploaded code or shell. */
function recovery_kit_sources(): array {
 $root=dirname(__DIR__);
 return ['start.py'=>$root.'/bin/recovery-bootstrap.py',
  'bin/fls_recovery_engine.py'=>$root.'/bin/fls_recovery_engine.py',
  'bin/system-backup.py'=>$root.'/bin/system-backup.py',
  'bin/provision-disk-management.py'=>$root.'/bin/provision-disk-management.py',
  'bin/fls_storage.py'=>$root.'/bin/fls_storage.py'];
}

function recovery_kit_trusted_open(string $path,int $maximum): array {
 backup_encryption_parent($path);clearstatcache(true,$path);$before=@lstat($path);
 if(!$before||($before['mode']&0170000)!==0100000||$before['uid']!==0
  ||($before['mode']&0022)!==0||$before['nlink']!==1||$before['size']<1||$before['size']>$maximum)throw new RecoveryDownloadError(503);
 $stream=@fopen($path,'rb');if(!$stream)throw new RecoveryDownloadError(503);
 $opened=fstat($stream);clearstatcache(true,$path);$current=@lstat($path);
 if(!$opened||!$current||!recovery_download_same_stat($before,$opened)||!recovery_download_same_stat($opened,$current)){
  fclose($stream);throw new RecoveryDownloadError(503);
 }
 return ['stream'=>$stream,'stat'=>$opened,'path'=>$path,'bytes'=>$opened['size']];
}

function recovery_kit_check_file(array $entry): void {
 $opened=fstat($entry['stream']);clearstatcache(true,$entry['path']);$current=@lstat($entry['path']);
 if(!$opened||!$current||!recovery_download_same_stat($entry['stat'],$opened)
  ||!recovery_download_same_stat($opened,$current))throw new RecoveryDownloadError(503);
}

function recovery_kit_runtime(): array {
 $directory=recovery_download_directory(RECOVERY_KIT_RUNTIME);
 $stream=recovery_download_open(RECOVERY_KIT_RUNTIME.'/runtime.json',$directory['gid'],65536);
 try{
  $before=fstat($stream);$text=stream_get_contents($stream);$after=fstat($stream);
  if(!is_string($text)||!$before||!$after||strlen($text)!==$before['size']||!recovery_download_same_stat($before,$after))throw new RecoveryDownloadError(503);
  $value=json_decode($text,true,16,JSON_THROW_ON_ERROR);
 }finally{fclose($stream);}
 if(!is_array($value)||array_is_list($value)||($value['schema']??null)!=='fls-recovery-runtime-v1'
  ||($value['filename']??null)!=='runtime.tar.gz'||!is_int($value['bytes']??null)||$value['bytes']<1||$value['bytes']>RECOVERY_KIT_MAX_RUNTIME
  ||!is_string($value['sha256']??null)||preg_match('/^[a-f0-9]{64}$/D',$value['sha256'])!==1
  ||($value['ubuntu']??null)!=='24.04'||($value['architecture']??null)!=='amd64'
  ||!is_int($value['package_count']??null)||$value['package_count']<1||$value['package_count']>10000
  ||!is_string($value['created_at_utc']??null)||preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/D',$value['created_at_utc'])!==1)throw new RecoveryDownloadError(503);
 try{new DateTimeImmutable($value['created_at_utc']);$errors=DateTimeImmutable::getLastErrors();if($errors&&($errors['warning_count']||$errors['error_count']))throw new RecoveryDownloadError(503);}
 catch(Throwable $error){throw new RecoveryDownloadError(503);}
 $path=RECOVERY_KIT_RUNTIME.'/runtime.tar.gz';
 $stream=recovery_download_open($path,$directory['gid'],$value['bytes'],$value['bytes']);
 return ['stream'=>$stream,'stat'=>fstat($stream),'path'=>$path,'bytes'=>$value['bytes'],'expected_sha256'=>$value['sha256']];
}

/** Fixed names fit USTAR; totals are known without buffering the tar or runtime. */
function recovery_kit_tar_header(string $name,int $bytes,int $mode,int $mtime): string {
 if(strlen($name)>100||preg_match('/^fls-recovery\/[A-Za-z0-9_.\/-]+$/D',$name)!==1
  ||str_contains($name,'..')||$bytes<0||$bytes>8589934591)throw new RecoveryDownloadError(503);
 $octal=static fn(int $value,int $length):string=>str_pad(decoct($value),$length-1,'0',STR_PAD_LEFT)."\0";
 $header=str_pad($name,100,"\0").$octal($mode,8).$octal(0,8).$octal(0,8)
  .$octal($bytes,12).$octal($mtime,12).str_repeat(' ',8).'0'.str_repeat("\0",100)
  ."ustar\00000".str_pad('root',32,"\0").str_pad('root',32,"\0")
  .$octal(0,8).$octal(0,8).str_repeat("\0",167);
 if(strlen($header)!==512)throw new RecoveryDownloadError(503);
 $checksum=array_sum(unpack('C*',$header));
 return substr_replace($header,str_pad(decoct($checksum),6,'0',STR_PAD_LEFT)."\0 ",148,8);
}

/** Same pinned descriptors are checked before headers and later streamed. */
function recovery_kit_tar(array $entries,int $mtime,callable $write): void {
 foreach($entries as $name=>$entry){
  $write(recovery_kit_tar_header('fls-recovery/'.$name,$entry['bytes'],$name==='start.py'?0755:0644,$mtime));
  if(isset($entry['text']))$write($entry['text']);
  else{
   recovery_kit_check_file($entry);
   if(!rewind($entry['stream']))throw new RecoveryDownloadError(503);
   $remaining=$entry['bytes'];$hash=hash_init('sha256');
   while($remaining>0){
    $chunk=fread($entry['stream'],min(1048576,$remaining));
    if(!is_string($chunk)||$chunk==='')throw new RecoveryDownloadError(503);
    $remaining-=strlen($chunk);hash_update($hash,$chunk);$write($chunk);
   }
   $digest=hash_final($hash);recovery_kit_check_file($entry);
   if(isset($entry['expected_sha256'])&&!hash_equals($entry['expected_sha256'],$digest))throw new RecoveryDownloadError(503);
  }
  $padding=(512-$entry['bytes']%512)%512;if($padding)$write(str_repeat("\0",$padding));
 }
 $write(str_repeat("\0",1024));
}

function recovery_kit_close(array $entries): void {
 foreach($entries as $entry)if(isset($entry['stream'])&&is_resource($entry['stream']))fclose($entry['stream']);
}

function recovery_kit_download(): never {
 header('Cache-Control: private, no-store, max-age=0');
 system_backups_admin('GET');
 foreach($_GET as $key=>$value)if(!in_array($key,['route','id'],true)||!is_string($value))throw new ManagementError('Kurtarma paketi isteği geçersiz.',422);
 $id=system_backups_int($_GET,'id');
 $backup=query("SELECT id,filename,bytes,sha256,verified_at FROM system_backups WHERE id=? AND status='ready' AND verified_at IS NOT NULL",[$id])[0]??null;
 if(!$backup||!is_string($backup['filename']??null)||preg_match('/^fls-system-\d{8}-\d{6}Z\.tar\.gz$/D',$backup['filename'])!==1
  ||system_backups_number($backup['bytes']??null,1)===null||!is_string($backup['sha256']??null)
  ||preg_match('/^[a-f0-9]{64}$/D',$backup['sha256'])!==1||system_backups_time($backup['verified_at']??null)===null)throw new ManagementError('Doğrulanmış sistem yedeği bulunamadı.',404);
 $backup['id']=$id;$backup['bytes']=(int)$backup['bytes'];$entries=[];
 try{
  foreach(recovery_kit_sources() as $name=>$path)$entries[$name]=recovery_kit_trusted_open($path,4194304);
  $entries['runtime.tar.gz']=recovery_kit_runtime();$runtime=$entries['runtime.tar.gz'];
  $identity=recovery_kit_trusted_open(RECOVERY_KIT_MACHINE_ID,128);
  try{$machine=trim(stream_get_contents($identity['stream']));recovery_kit_check_file($identity);}
  finally{fclose($identity['stream']);}
  if(preg_match('/^[a-f0-9]{32}$/D',$machine)!==1)throw new RecoveryDownloadError(503);
  $copies=[];
  foreach(backup_encryption_companions($backup) as $copy){
   $value=backup_encryption_companion($backup,$copy['key_id']);
   $copies[]=array_intersect_key($value,array_flip(['filename','bytes','sha256','key_id','recipient']));
  }
  $now=new DateTimeImmutable('now',new DateTimeZone('UTC'));
  $plan=['schema'=>'fls-recovery-plan-v1','mode'=>'single-disk-rehearsal','created_at'=>$now->format('Y-m-d\TH:i:s\Z'),
   'source_machine_sha256'=>hash('sha256',$machine),'backup'=>array_intersect_key($backup,array_flip(['filename','bytes','sha256'])),
   'encrypted_copies'=>$copies,'runtime'=>['sha256'=>$runtime['expected_sha256'],'bytes'=>$runtime['bytes']]];
  $text=json_encode($plan,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR)."\n";
  $entries['plan.json']=['text'=>$text,'bytes'=>strlen($text)];
  $text="FLS — Yeni Ubuntu üzerinde tek diskli kurtarma provası\n\nBu paket yedek dosyasını veya özel kurtarma anahtarını içermez.\nSeçilen yedek: ".$backup['filename']."\nSHA-256: ".$backup['sha256']."\n\nYeni Ubuntu 24.04 amd64 cihazda paketi açın ve fls-recovery klasöründe:\n  sudo python3 start.py\n\nYedeği ve gerekiyorsa dışarıda sakladığınız kurtarma anahtarını hedefte açılan sihirbaza verin.\nBu paket kaynak/üretim sunucusunda geri yükleme başlatmaz; aynı kaynak makinede çalışmayı reddeder.\nİşletim sistemi imajı ve geçmiş log/arşiv verileri bu yedekte yoktur.\nProva sonunda bakım modu korunur; ücretli zaman damgası ve dış aktarımlar otomatik açılmaz.\n";
  $entries['README.txt']=['text'=>$text,'bytes'=>strlen($text)];
  @set_time_limit(0);$hash=hash_init('sha256');$bytes=0;
  recovery_kit_tar($entries,$now->getTimestamp(),static function(string $chunk)use($hash,&$bytes):void{hash_update($hash,$chunk);$bytes+=strlen($chunk);});
  $digest=hash_final($hash);
  system_backups_admin('GET');
  foreach($entries as $entry)if(isset($entry['stream']))recovery_kit_check_file($entry);
  $filename='fls-recovery-kit-'.$id.'.tar';$url='/api.php?route=system_recovery_kit&id='.$id;
  if(($_SERVER['HTTP_ACCEPT']??'')==='application/json'){
   recovery_kit_close($entries);json_response(['ready'=>true,'filename'=>$filename,'bytes'=>$bytes,'download_url'=>$url]);
  }
  recovery_download_headers($filename,'application/x-tar',$bytes,$digest,$backup['sha256']);
 }catch(Throwable $error){
  recovery_kit_close($entries);
  if($error instanceof ManagementError)throw $error;
  throw new ManagementError('Kurtarma başlangıç paketi henüz hazır değil veya doğrulanamadı. Yedek korunuyor; yönetici paket hazırlığını kontrol etmeli.',503);
 }
 try{recovery_kit_tar($entries,$now->getTimestamp(),static function(string $chunk):void{echo $chunk;});}
 catch(Throwable $error){error_log('FLS recovery kit stream interrupted: '.get_class($error));}
 finally{recovery_kit_close($entries);}
 exit;
}
