<?php
declare(strict_types=1);
// Host-wide archive health. Never join raw events or expose provider credentials.
function timestamp_age(?string $value, int $now): ?int {
 if(!$value)return null;
 return max(0,$now-(new DateTimeImmutable($value,new DateTimeZone('UTC')))->getTimestamp());
}
function timestamp_dashboard(): array {
 $now=time();$s=query('SELECT * FROM timestamp_settings WHERE id=1')[0];
 $p=query('SELECT provider,environment,check_status,checked_revision,revision,balance,balance_status,balance_at,balance_attempted_at,balance_basis_attempt_id FROM timestamp_profiles WHERE provider=?',[$s['provider']])[0];
 // Include jobs from earlier scopes and eligible hours not yet inserted by the worker.
 // Queue age uses an immutable creation time; normal worker updates cannot reset it.
 $w=query("SELECT COUNT(*) total,COALESCE(SUM(t.status='processing'),0) processing,COALESCE(SUM(t.status='error'),0) errors,COALESCE(SUM(t.status='uncertain'),0) uncertain,MIN(COALESCE(t.created_at,GREATEST(COALESCE(p.created_at,m.signed_at),COALESCE(?,p.created_at,m.signed_at)))) oldest_at FROM archive_packages p JOIN archive_manifests m ON m.id=p.manifest_id LEFT JOIN timestamp_stamps t ON t.manifest_id=p.manifest_id WHERE (t.id IS NOT NULL AND t.status<>'verified') OR (t.id IS NULL AND p.status='ready' AND m.status='verified' AND ?>0 AND p.manifest_id>=?)",[$s['scope_started_at'],$s['start_manifest_id'],$s['start_manifest_id']])[0];
 foreach(['total','processing','errors','uncertain'] as $k)$w[$k]=(int)$w[$k];$w['oldest_seconds']=timestamp_age($w['oldest_at'],$now);
 $last=query("SELECT t.stamp_at,t.verified_at,t.provider,m.source_file FROM timestamp_stamps t JOIN archive_manifests m ON m.id=t.manifest_id WHERE t.status='verified' ORDER BY t.stamp_at DESC,t.id DESC LIMIT 1")[0]??null;
 $local=query("SELECT COUNT(*) total,COALESCE(SUM(status<>'verified'),0) failures,MAX(verified_at) checked_at,MAX(signed_at) signed_at FROM archive_manifests")[0];
 $worker=query('SELECT checked_at,status,error_code FROM timestamp_worker WHERE id=1')[0]??null;
 $later=(int)query("SELECT COUNT(*) n FROM timestamp_attempts WHERE provider=? AND profile_revision=? AND id>? AND status<>'prepared'",[$p['provider'],$p['revision'],$p['balance_basis_attempt_id']])[0]['n'];
 $credit=['environment'=>$p['environment'],'remaining'=>$p['balance']===null?null:(int)$p['balance'],'status'=>$p['balance_status'],'observed_at'=>$p['balance_at'],'attempted_at'=>$p['balance_attempted_at'],'fresh'=>$p['environment']==='production'&&$p['balance']!==null&&$p['balance_at']!==null&&$p['balance_status']==='ok'&&timestamp_age($p['balance_at'],$now)<=1800&&$later===0,'unreflected_requests'=>$later,'threshold'=>(int)$s['low_credit_threshold']];
 $active=$s['signing_mode']==='provider'&&(bool)$s['enabled'];$alerts=[];
 $add=function($code,$severity,$message,$destination='archive')use(&$alerts){$alerts[]=['code'=>$code,'severity'=>$severity,'message'=>$message,'destination'=>$destination];};
 if((int)$local['failures']>0)$add('local_integrity','error','Yerel arşiv bütünlüğü doğrulanamadı. İmza zincirini kontrol edin.');
 elseif((int)$local['total']>0&&(!$local['checked_at']||timestamp_age($local['checked_at'],$now)>7200))$add('local_check_stale','warning','Yerel imza zincirinin son doğrulaması iki saati geçti.');
 if($active){
  if($p['environment']!=='production'||$p['check_status']!=='ok'||(int)$p['checked_revision']!==(int)$p['revision'])$add('provider_unready','error','Seçili üretim hesabı doğrulanmış değil; otomatik damga alınamıyor.','settings');
  if(!$worker||timestamp_age($worker['checked_at'],$now)>600||$worker['status']==='error')$add('worker_stale','error','Zaman damgası işçisi yanıt vermiyor veya hata bildirdi.');
  if($credit['fresh']&&$credit['remaining']<=$credit['threshold'])$add($credit['remaining']===0?'credit_empty':'credit_low',$credit['remaining']===0?'error':'warning',$credit['remaining']===0?'Sağlayıcı zaman damgası kredisi tükendi.':'Zaman damgası kredisi uyarı eşiğine indi.','settings');
  if(!$credit['fresh'])$add('credit_unavailable','warning',$p['balance_status']==='error'?'Bakiye sorgusu başarısız; kalan kredi doğrulanamıyor.':'Kalan kredi henüz güncel olarak doğrulanmadı.','settings');
  if($w['errors']||$w['uncertain'])$add('stamp_failed','error',"{$w['errors']} hatalı, {$w['uncertain']} sonucu belirsiz damga işi var. Belirsiz istekler otomatik yinelenmez.");
  if($w['total']&&$w['oldest_seconds']>=(int)$s['stall_minutes']*60)$add('stamp_delayed','warning',"Bekleyen arşivlerin damgalanması {$s['stall_minutes']} dakikalık süreyi aştı.");
 }elseif($s['signing_mode']==='provider')$add('provider_paused','warning',$w['total']?'Sağlayıcı damgalaması duraklatıldı; bekleyen arşivler korunuyor.':'Sağlayıcı damgalaması etkin değil. Yerel imza zinciri çalışmaya devam ediyor.','settings');
 $accepted=(int)$s['local_acceptance_version']===1&&$s['local_accepted_at']!==null;
 $localHealthy=(int)$local['failures']===0&&$local['checked_at']!==null&&timestamp_age($local['checked_at'],$now)<=7200;
 $fallback=$localHealthy&&$s['signing_mode']==='provider'&&(bool)$s['allow_local_fallback']&&$accepted&&(!$active||count(array_filter($alerts,fn($a)=>in_array($a['code'],['provider_unready','worker_stale','credit_empty','stamp_failed','stamp_delayed'],true)))>0);
 return ['scope'=>'server','checked_at'=>gmdate('Y-m-d H:i:s',$now),'mode'=>$s['signing_mode'],'enabled'=>$active,'provider'=>$p['provider'],'provider_name'=>timestamp_providers()[$p['provider']]['name'],'local_fallback_enabled'=>(bool)$s['allow_local_fallback'],'local_fallback_active'=>$fallback,'local_accepted'=>$accepted,'credit'=>$credit,'waiting'=>$w,'last_success'=>$last,'local'=>['total'=>(int)$local['total'],'failures'=>(int)$local['failures'],'signed_at'=>$local['signed_at'],'checked_at'=>$local['checked_at']],'stall_minutes'=>(int)$s['stall_minutes'],'alerts'=>$alerts];
}
