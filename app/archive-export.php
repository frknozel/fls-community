<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
function archive_export_page(string $key): int {
 $v=$_GET[$key]??'1';if(!is_string($v)||!preg_match('/^[1-9][0-9]{0,6}$/D',$v))throw new ManagementError('Sayfa numarası geçersiz.');return (int)$v;
}
function archive_tls_trust(mixed $value): string {
 if(!is_string($value)||strlen($value)>12000)throw new ManagementError('FTPS güven sertifikası en fazla 12.000 bayt olmalı.');
 $value=trim($value);if($value==='')return '';
 // Exactly one public certificate; never accept private keys or appended material.
 if(!preg_match('~\A-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+\s+-----END CERTIFICATE-----\z~D',$value))throw new ManagementError('Tek bir açık PEM sertifikası girin; özel anahtar eklemeyin.');
 $certificate=@openssl_x509_read($value);$info=$certificate?@openssl_x509_parse($certificate):false;
 if(!$info||!openssl_x509_export($certificate,$pem))throw new ManagementError('FTPS sertifikası okunamadı.');
 if(($info['validTo_time_t']??0)<=time()||($info['validFrom_time_t']??PHP_INT_MAX)>time())throw new ManagementError('FTPS sertifikasının geçerlilik tarihlerini kontrol edin.');
 return $pem;
}
function archive_tls_info(string $pem): ?array {
 if($pem==='')return null;$cert=@openssl_x509_read($pem);$info=$cert?@openssl_x509_parse($cert):false;
 return $info?['sha256'=>openssl_x509_fingerprint($cert,'sha256'),'expires_at'=>gmdate('Y-m-d H:i:s',$info['validTo_time_t']),'expires_in_days'=>(int)floor(($info['validTo_time_t']-time())/86400)]:null;
}
function archive_export_snapshot(): array {
 $packageTotal=(int)query('SELECT COUNT(*) n FROM archive_packages')[0]['n'];$deliveryTotal=(int)query('SELECT COUNT(*) n FROM archive_deliveries')[0]['n'];
 $packagePage=min(archive_export_page('archive_page'),max(1,(int)ceil($packageTotal/25)));$deliveryPage=min(archive_export_page('delivery_page'),max(1,(int)ceil($deliveryTotal/25)));
 $dest=query("SELECT id,name,protocol,host,port,remote_path,share_name,username,domain_name,host_key,tls_trust_pem,enabled,start_manifest_id,revision,check_status,check_code,observed_host_key,checked_at,checked_revision,created_at,updated_at FROM archive_destinations ORDER BY id");
 foreach($dest as &$destination)$destination['tls_trust']=archive_tls_info($destination['tls_trust_pem']);unset($destination);
 return ['settings'=>query('SELECT * FROM archive_export_settings WHERE id=1')[0], 'destinations'=>$dest,
 'worker'=>query('SELECT * FROM archive_export_worker WHERE id=1')[0]??null,
 'metrics'=>query("SELECT COUNT(*) total,COALESCE(SUM(p.status='ready'),0) ready,COALESCE(SUM(p.manifest_id IS NULL OR p.status<>'ready'),0) pending,COALESCE(SUM(p.bytes),0) bytes FROM archive_manifests m LEFT JOIN archive_packages p ON p.manifest_id=m.id WHERE m.status='verified'")[0],
 'packages'=>query("SELECT p.*,m.source_file,m.rows_count,m.signed_at,m.status manifest_status FROM archive_packages p JOIN archive_manifests m ON m.id=p.manifest_id ORDER BY m.source_file DESC LIMIT 25 OFFSET ".(($packagePage-1)*25)),
 'deliveries'=>query('SELECT j.*,d.name destination_name,d.revision current_revision,m.source_file FROM archive_deliveries j JOIN archive_destinations d ON d.id=j.destination_id JOIN archive_manifests m ON m.id=j.manifest_id ORDER BY j.id DESC LIMIT 25 OFFSET '.(($deliveryPage-1)*25)),
 'delivery_totals'=>query("SELECT destination_id,destination_revision,status,COUNT(*) count FROM archive_deliveries GROUP BY destination_id,destination_revision,status"),
 'pagination'=>['packages'=>['page'=>$packagePage,'pages'=>max(1,(int)ceil($packageTotal/25)),'total'=>$packageTotal],'deliveries'=>['page'=>$deliveryPage,'pages'=>max(1,(int)ceil($deliveryTotal/25)),'total'=>$deliveryTotal]],
 'qualified_timestamp'=>false];
}
function archive_export_secret(string $value): string {
 if(strlen($value)>20000 || str_contains($value,"\0"))throw new ManagementError('Gizli bilgi geçersiz.');
 $key=@file_get_contents('/etc/fls/credential-key');if($key===false||strlen($key)!==32)throw new ManagementError('Anahtar kasası hazır değil.',503);
 $iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($value,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,'FLS-Archive-v1',16);
 if($cipher===false)throw new ManagementError('Bilgi şifrelenemedi.',503);return 'v1:'.base64_encode($iv.$cipher.$tag);
}
function archive_export_write(string $route,array $data): array {
 $pdo=db();$pdo->beginTransaction();
 try {
  query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
  $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$_SESSION['uid']])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  if($route==='save_archive_settings'){
   $old=query('SELECT * FROM archive_export_settings WHERE id=1 FOR UPDATE')[0];
   if(management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Ayar değişti; ekranı yenileyin.',409);
   execute('UPDATE archive_export_settings SET packaging_enabled=?,revision=revision+1,updated_by=?,updated_at=UTC_TIMESTAMP(6) WHERE id=1',[management_bool($data,'packaging_enabled'),$_SESSION['username']]);
   audit('archive_settings','hourly packaging updated');
  }elseif($route==='save_archive_destination'){
   require_once __DIR__.'/archive-tls-history.php';
   query('SELECT id FROM archive_tls_history_state WHERE id=1 FOR UPDATE');
   $id=isset($data['id'])&&$data['id']!==''?management_int($data,'id'):0;
   $old=$id?(query('SELECT * FROM archive_destinations WHERE id=? FOR UPDATE',[$id])[0]??null):null;
   if($id&&!$old)throw new ManagementError('Hedef bulunamadı.',404);
   if($old&&management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Hedef değişti; ekranı yenileyin.',409);
   if(!$id&&(int)query('SELECT COUNT(*) n FROM archive_destinations')[0]['n']>=8)throw new ManagementError('En fazla 8 yedekleme hedefi tanımlanabilir.');
   $name=management_text($data,'name',100);$protocol=management_enum($data,'protocol',['ftp','ftps','sftp','scp','smb']);
   $host=strtolower(management_text($data,'host',253));
   if(filter_var($host,FILTER_VALIDATE_IP))$host=management_ip($host);
   elseif(!preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/D',$host)||str_contains($host,'..')||$host==='localhost')throw new ManagementError('Sunucu için IP veya DNS adı girin.');
   $port=management_int($data,'port',1,65535);$path=management_text($data,'remote_path',400,false);
   if($path===''||!preg_match('~^/?[A-Za-z0-9_. /()-]*$~D',$path)||preg_match('~(^|/)\.\.?(/|$)~',$path)||str_starts_with($path,'-'))throw new ManagementError('Hedef klasör yolunu girin. Harf, rakam, boşluk, /, _, -, nokta ve parantez kullanılabilir; üst dizin geçişi kullanılamaz.');
   $user=management_text($data,'username',120);$domain=management_text($data,'domain_name',100,false);$share=management_text($data,'share_name',100,false);
   if(!preg_match('/^[A-Za-z0-9_.@ -]+$/D',$user)||($domain!==''&&!preg_match('/^[A-Za-z0-9_.-]+$/D',$domain)))throw new ManagementError('Kullanıcı veya etki alanı geçersiz.');
   if($protocol==='smb'&&!preg_match('/^[A-Za-z0-9_ .()-]+$/D',$share))throw new ManagementError('SMB paylaşım adını girin.');
   $pin=management_text($data,'host_key',100,false);
   if($pin!==''&&!preg_match('~^SHA256:[A-Za-z0-9+/]{43}$~D',$pin))throw new ManagementError('SSH sunucu izi SHA256: biçiminde olmalı.');
   $trust=array_key_exists('tls_trust_pem',$data)?archive_tls_trust($data['tls_trust_pem']):($old['tls_trust_pem']??'');
   $enabled=management_bool($data,'enabled');if(in_array($protocol,['scp','sftp'],true)&&$enabled&&$pin==='')throw new ManagementError('Etkin SSH hedefi için doğrulanmış sunucu izi gerekli.');
   $password=$data['password']??'';$private=$data['private_key']??'';
   if(!is_string($password)||!is_string($private)||strlen($password)>4096||strlen($private)>16000||preg_match('/[\r\n\x00]/',$password)||str_contains($private,"\0"))throw new ManagementError('Parola veya özel anahtar geçersiz.');
   if($private!==''&&!in_array($protocol,['sftp','scp'],true))throw new ManagementError('Özel anahtar yalnızca SSH hedefinde kullanılabilir.');
   $cipher=$old['secret_cipher']??'';
   if($password!==''||$private!=='')$cipher=archive_export_secret(json_encode(['password'=>$password,'private_key'=>$private],JSON_THROW_ON_ERROR));
   if($cipher==='')throw new ManagementError('Parola veya SSH özel anahtarı girin.');
   $start=$old['start_manifest_id']??(management_bool($data,'include_existing')?1:(int)query('SELECT COALESCE(MAX(id),0)+1 n FROM archive_manifests')[0]['n']);
   $values=[$name,$protocol,$host,$port,rtrim($path,'/').'/', $share,$user,$domain,$cipher,$pin,$trust,$enabled,$start];
   if($old){
    execute("UPDATE archive_destinations SET name=?,protocol=?,host=?,port=?,remote_path=?,share_name=?,username=?,domain_name=?,secret_cipher=?,host_key=?,tls_trust_pem=?,enabled=?,start_manifest_id=?,revision=revision+1,check_status='untested',check_code='',observed_host_key='',test_requested_at=NULL,checked_revision=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=?",[...$values,$id]);
    execute("UPDATE archive_deliveries SET status='cancelled',error_code='destination_changed' WHERE destination_id=? AND status IN ('pending','retry','uploading')",[$id]);
   }else{
    execute('INSERT INTO archive_destinations(name,protocol,host,port,remote_path,share_name,username,domain_name,secret_cipher,host_key,tls_trust_pem,enabled,start_manifest_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',$values);$id=(int)$pdo->lastInsertId();
   }
   audit('archive_destination','destination_id='.$id.';protocol='.$protocol.';enabled='.$enabled);
   archive_tls_history_reconcile();
  }elseif($route==='test_archive_destination'){
   $id=management_int($data,'id');if(!query('SELECT id FROM archive_destinations WHERE id=?',[$id]))throw new ManagementError('Hedef bulunamadı.',404);
   execute("UPDATE archive_destinations SET test_requested_at=UTC_TIMESTAMP(6),check_status='pending',check_code='' WHERE id=?",[$id]);audit('archive_test','destination_id='.$id);
  }elseif($route==='retry_archive_delivery'){
   $id=management_int($data,'id');$job=query('SELECT j.*,d.revision,d.enabled FROM archive_deliveries j JOIN archive_destinations d ON d.id=j.destination_id WHERE j.id=? FOR UPDATE',[$id])[0]??null;
   if(!$job)throw new ManagementError('Aktarım bulunamadı.',404);
   if(!(int)$job['enabled']||(int)$job['revision']!==(int)$job['destination_revision']||!in_array($job['status'],['retry','pending'],true))throw new ManagementError('Bu aktarım yeniden başlatılamaz.',409);
   execute('UPDATE archive_deliveries SET next_attempt_at=NULL WHERE id=?',[$id]);audit('archive_retry','delivery_id='.$id);
  }else throw new ManagementError('İşlem bulunamadı.',404);
  $pdo->commit();return ['saved'=>true];
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
function archive_package_download(): never {
 $id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);if(!$id)throw new ManagementError('Paket kimliği geçersiz.');
 $r=query("SELECT p.* FROM archive_packages p JOIN archive_manifests m ON m.id=p.manifest_id WHERE p.manifest_id=? AND p.status='ready' AND m.status='verified'",[$id])[0]??null;
 if(!$r||!preg_match('/^fls-[0-9-]{13}-[a-f0-9]{16}\.tar\.gz$/D',$r['filename']))throw new ManagementError('Doğrulanmış paket hazır değil.',404);
 $path='/srv/fls-server/archive/packages/'.$r['filename'];$s=@lstat($path);
 if(!$s||($s['mode']&0170000)!==0100000||$s['size']!==(int)$r['bytes'])throw new ManagementError('Paket kullanılamıyor.',409);
 $f=@fopen($path,'rb');if(!$f)throw new ManagementError('Paket okunamıyor.',503);
 // The directory is worker-owned; web users have no write access.
 $h=hash_init('sha256');hash_update_stream($h,$f);if(!hash_equals($r['sha256'],hash_final($h))){fclose($f);throw new ManagementError('Paket bütünlük kontrolü başarısız.',409);}rewind($f);
 audit('archive_download','manifest_id='.$id);
 header('Content-Type: application/gzip');header('Content-Disposition: attachment; filename="'.$r['filename'].'"');header('Content-Length: '.$r['bytes']);header('X-Archive-SHA256: '.$r['sha256']);header('Cache-Control: private, no-store');set_time_limit(0);fpassthru($f);fclose($f);exit;
}
