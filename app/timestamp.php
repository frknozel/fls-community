<?php
declare(strict_types=1);
require_once __DIR__.'/management.php';
require_once __DIR__.'/timestamp-monitor.php';
function timestamp_providers(): array {return [
 'kamusm'=>['name'=>'KamuSM','production'=>'http://zd.kamusm.gov.tr','test'=>'http://tzd.kamusm.gov.tr','apply_url'=>'https://zdportal.kamusm.gov.tr/','docs_url'=>'https://kamusm.bilgem.tubitak.gov.tr/urunler/zaman_damgasi/ucretsiz_zaman_damgasi_istemci_yazilimi.jsp'],
 'turktrust'=>['name'=>'TÜRKTRUST','production'=>'http://zd.turktrust.com.tr','apply_url'=>'https://onlineislemler.turktrust.com.tr/zamanDamgasiKullaniciKaydet.xhtml','docs_url'=>'https://www.turktrust.com.tr/zaman-damgasi.html']
];}
function timestamp_snapshot(): array {
 $profiles=query("SELECT provider,environment,customer_id,revision,check_status,check_code,checked_revision,checked_at,test_requested_at,balance_status,balance,balance_at,balance_attempted_at,updated_at,(secret_cipher<>'') has_secret FROM timestamp_profiles ORDER BY provider");
 $sources=json_decode(@file_get_contents(__DIR__.'/../deploy/tsa/sources.json')?:'{}',true)??[];
 return ['settings'=>query('SELECT * FROM timestamp_settings WHERE id=1')[0],'providers'=>timestamp_providers(),'profiles'=>$profiles,
 'worker'=>query('SELECT * FROM timestamp_worker WHERE id=1')[0]??null,
 'metrics'=>query("SELECT COUNT(*) total,COALESCE(SUM(status='verified'),0) verified,COALESCE(SUM(status='pending'),0) pending,COALESCE(SUM(status IN ('error','uncertain')),0) attention FROM timestamp_stamps")[0],
 'available_packages'=>(int)query("SELECT COUNT(*) n FROM archive_packages p JOIN archive_manifests m ON m.id=p.manifest_id WHERE p.status='ready' AND m.status='verified' AND NOT EXISTS (SELECT 1 FROM timestamp_stamps s WHERE s.manifest_id=p.manifest_id AND s.status='verified')")[0]['n'],
 'stamps'=>query('SELECT s.*,m.source_file,COALESCE(a.response_sha256<>\'\',0) has_response FROM timestamp_stamps s JOIN archive_manifests m ON m.id=s.manifest_id LEFT JOIN timestamp_attempts a ON a.attempt_key=s.attempt_key ORDER BY s.manifest_id DESC LIMIT 25'),
 'deliveries'=>query('SELECT j.id,j.stamp_id,j.status,j.attempts,j.error_code,j.completed_at,d.name destination_name,m.source_file FROM timestamp_deliveries j JOIN timestamp_stamps s ON s.id=j.stamp_id JOIN archive_manifests m ON m.id=s.manifest_id JOIN archive_destinations d ON d.id=j.destination_id ORDER BY j.id DESC LIMIT 25'),
 'trust_roots'=>array_map(fn($r)=>array_intersect_key($r,array_flip(['provider','subject','sha256','not_after'])),$sources['roots']??[]),
 'runtime_installed'=>is_file('/opt/fls-tsa/FlsTsaBridge.class')&&is_file('/opt/fls-tsa/client.jar')&&is_file('/opt/fls-tsa/client-license.xml'),
 'commercial_account_tested'=>count(array_filter($profiles,fn($p)=>$p['check_status']==='ok'&&(int)$p['checked_revision']===(int)$p['revision']&&$p['environment']==='production'))>0];
}
function timestamp_encrypt(string $secret): string {
 $key=@file_get_contents('/etc/fls/credential-key');if($key===false||strlen($key)!==32)throw new ManagementError('Anahtar kasası hazır değil.',503);
 $iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($secret,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,'FLS-Timestamp-v1',16);
 if($cipher===false)throw new ManagementError('Parola şifrelenemedi.',503);return 'v1:'.base64_encode($iv.$cipher.$tag);
}
function timestamp_write(string $route,array $data): array {
 $pdo=db();$pdo->beginTransaction();
 try {
  query('SELECT id FROM management_lock WHERE id=1 FOR UPDATE');
  $actor=query('SELECT role,enabled,session_version FROM users WHERE id=? FOR UPDATE',[$_SESSION['uid']])[0]??null;
  if(!$actor||$actor['role']!=='admin'||!(int)$actor['enabled']||(int)$actor['session_version']!==(int)($_SESSION['session_version']??0))throw new ManagementError('Yönetim yetkiniz değişti.',403);
  $settings=query('SELECT * FROM timestamp_settings WHERE id=1 FOR UPDATE')[0];
  if($route==='save_timestamp_profile'){
   $provider=management_enum($data,'provider',array_keys(timestamp_providers()));$old=query('SELECT * FROM timestamp_profiles WHERE provider=? FOR UPDATE',[$provider])[0];
   if(management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Sağlayıcı ayarı değişti; ekranı yenileyin.',409);
   if($settings['signing_mode']==='provider'&&(int)$settings['enabled']&&$settings['provider']===$provider)throw new ManagementError('Etkin hesabı değiştirmek için önce otomatik damgalamayı duraklatın.',409);
   $environment=management_enum($data,'environment',$provider==='kamusm'?['production','test']:['production']);$id=management_text($data,'customer_id',10);
   if(!preg_match('/^[1-9][0-9]{0,8}$/D',$id))throw new ManagementError('ESYA uyumlu sayısal müşteri numarasını girin.');
   $password=$data['password']??'';if(!is_string($password)||strlen($password)>512||preg_match('/[\x00-\x1f\x7f]/',$password))throw new ManagementError('Parola geçersiz.');
   $cipher=$password!==''?timestamp_encrypt($password):$old['secret_cipher'];
   if($cipher==='')throw new ManagementError('Sağlayıcı parolasını girin.');
   if($password===''&&$id!==$old['customer_id'])throw new ManagementError('Müşteri numarası değiştiğinde parolayı yeniden girin.');
   execute("UPDATE timestamp_profiles SET environment=?,customer_id=?,secret_cipher=?,revision=revision+1,check_status='untested',check_code='',checked_revision=NULL,test_requested_at=NULL,balance_requested_at=NULL,balance_status='unknown',balance=NULL,balance_at=NULL,balance_attempted_at=NULL,balance_basis_attempt_id=0,updated_at=UTC_TIMESTAMP(6) WHERE provider=?",[$environment,$id,$cipher,$provider]);
   audit('timestamp_profile','provider='.$provider.';environment='.$environment);
  }elseif(in_array($route,['test_timestamp_profile','timestamp_balance'],true)){
   $provider=management_enum($data,'provider',array_keys(timestamp_providers()));$old=query('SELECT * FROM timestamp_profiles WHERE provider=? FOR UPDATE',[$provider])[0];
   if($old['secret_cipher']==='')throw new ManagementError('Önce sağlayıcı hesabını kaydedin.');
   if(management_int($data,'revision')!==(int)$old['revision'])throw new ManagementError('Sağlayıcı ayarı değişti; ekranı yenileyin.',409);
   if($route==='test_timestamp_profile'){
    if($old['check_status']==='pending')throw new ManagementError('Sınama zaten sırada.',409);
    execute("UPDATE timestamp_profiles SET test_requested_at=UTC_TIMESTAMP(6),check_status='pending',check_code='' WHERE provider=?",[$provider]);
   }else execute("UPDATE timestamp_profiles SET balance_requested_at=UTC_TIMESTAMP(6),balance_status='pending' WHERE provider=?",[$provider]);
   audit($route,'provider='.$provider);
  }elseif($route==='save_timestamp_settings'){
   if(management_int($data,'revision')!==(int)$settings['revision'])throw new ManagementError('Damgalama ayarı değişti; ekranı yenileyin.',409);
   $enabled=management_bool($data,'enabled');$provider=management_enum($data,'provider',array_keys(timestamp_providers()));$existing=management_bool($data,'include_existing');
   $mode=management_enum($data,'signing_mode',['provider','local']);$fallback=management_bool($data,'allow_local_fallback');
   $threshold=management_int($data,'low_credit_threshold',0,1000000000);$delay=management_int($data,'stall_minutes',5,1440);
   $accept=management_bool($data,'accept_local_risk');
   $accepted=(int)$settings['local_acceptance_version']===1&&$settings['local_accepted_at']!==null;
   if(($mode==='local'||$fallback)&&!$accepted&&!$accept)throw new ManagementError('Yerel imzanın sağlayıcı zaman damgası olmadığını kabul etmek için ilgili kutuyu işaretleyin.');
   if($mode==='local')$enabled=0;
   if($enabled){
    $profile=query('SELECT * FROM timestamp_profiles WHERE provider=? FOR UPDATE',[$provider])[0];
    if($profile['environment']!=='production'||$profile['check_status']!=='ok'||(int)$profile['checked_revision']!==(int)$profile['revision'])throw new ManagementError('Etkinleştirmeden önce üretim hesabıyla bir doğrulanmış deneme damgası alın.');
   }
   $start=(int)$settings['start_manifest_id'];if($enabled&&(!$start||$existing))$start=$existing?1:(int)query('SELECT COALESCE(MAX(id),0)+1 n FROM archive_manifests')[0]['n'];
   execute('UPDATE timestamp_settings SET enabled=?,provider=?,start_manifest_id=?,signing_mode=?,allow_local_fallback=?,low_credit_threshold=?,stall_minutes=?,scope_started_at=IF(? OR scope_started_at IS NULL,UTC_TIMESTAMP(6),scope_started_at),revision=revision+1,updated_by=?,updated_at=UTC_TIMESTAMP(6) WHERE id=1',[$enabled,$provider,$start,$mode,$fallback,$threshold,$delay,$start!==(int)$settings['start_manifest_id']?1:0,$_SESSION['username']]);
   $takeAcceptance=$accept&&($mode==='local'||$fallback);
   if($takeAcceptance)execute('UPDATE timestamp_settings SET local_accepted_at=UTC_TIMESTAMP(6),local_accepted_by=?,local_acceptance_version=1 WHERE id=1',[$_SESSION['username']]);
   audit('timestamp_settings','provider='.$provider.';enabled='.$enabled.';mode='.$mode.';fallback='.$fallback.';local_acceptance='.($accepted||$takeAcceptance?1:0).';credit_threshold='.$threshold.';stall_minutes='.$delay.';start_manifest_id='.$start);
  }elseif($route==='recheck_timestamp'){
   $id=management_int($data,'id');$stamp=query('SELECT s.*,a.response_sha256 FROM timestamp_stamps s JOIN timestamp_attempts a ON a.attempt_key=s.attempt_key WHERE s.id=? FOR UPDATE',[$id])[0]??null;
   if(!$stamp||$stamp['response_sha256']===''||!in_array($stamp['status'],['error','uncertain'],true))throw new ManagementError('Yeniden doğrulanabilecek kayıtlı yanıt yok.',409);
   execute("UPDATE timestamp_stamps SET status='processing',error_code='',updated_at=UTC_TIMESTAMP(6) WHERE id=?",[$id]);audit('timestamp_recheck','stamp_id='.$id.';new_credit=0');
  }elseif($route==='retry_timestamp'){
   $id=management_int($data,'id');$stamp=query('SELECT * FROM timestamp_stamps WHERE id=? FOR UPDATE',[$id])[0]??null;
   if(!$stamp)throw new ManagementError('Damga işi bulunamadı.',404);
   if($settings['signing_mode']!=='provider'||!(int)$settings['enabled']||!in_array($stamp['status'],['error','uncertain'],true))throw new ManagementError('Bu iş yeniden gönderilemez.',409);
   $profile=query('SELECT * FROM timestamp_profiles WHERE provider=? FOR UPDATE',[$settings['provider']])[0];
   if($profile['environment']!=='production'||$profile['check_status']!=='ok'||(int)$profile['checked_revision']!==(int)$profile['revision'])throw new ManagementError('Önce geçerli üretim hesabını sınayın.');
   execute("UPDATE timestamp_stamps SET status='pending',provider=?,profile_revision=?,attempt_key='',error_code='',updated_at=UTC_TIMESTAMP(6) WHERE id=?",[$profile['provider'],$profile['revision'],$id]);
   audit('timestamp_manual_retry','stamp_id='.$id.';may_consume_new_credit=1');
  }else throw new ManagementError('İşlem bulunamadı.',404);
  $pdo->commit();return ['saved'=>true];
 }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();throw $e;}
}
function timestamp_download(): never {
 $id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);if(!$id)throw new ManagementError('Damga kimliği geçersiz.');
 $row=query("SELECT filename,sha256,bytes FROM timestamp_stamps WHERE id=? AND status='verified'",[$id])[0]??null;
 if(!$row||!preg_match('/^fls-[0-9-]{13}-[a-f0-9]{16}\.tar\.gz\.timestamp-[a-f0-9]{16}\.tar\.gz$/D',$row['filename']))throw new ManagementError('Doğrulanmış damga belgesi bulunamadı.',404);
 $path='/srv/fls-server/archive/timestamps/proofs/'.$row['filename'];$stat=@lstat($path);
 if(!$stat||($stat['mode']&0170000)!==0100000||$stat['size']!==(int)$row['bytes'])throw new ManagementError('Damga dosyası kullanılamıyor.',409);
 $f=@fopen($path,'rb');if(!$f)throw new ManagementError('Dosya okunamadı.',503);$h=hash_init('sha256');hash_update_stream($h,$f);
 if(!hash_equals($row['sha256'],hash_final($h))){fclose($f);throw new ManagementError('Damga dosyası bütünlük hatası.',409);}rewind($f);audit('timestamp_download','stamp_id='.$id);
 header('Content-Type: application/gzip');header('Content-Disposition: attachment; filename="'.$row['filename'].'"');header('Content-Length: '.$row['bytes']);header('Cache-Control: private, no-store');fpassthru($f);fclose($f);exit;
}
