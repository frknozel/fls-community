'use strict';
(() => {
 const key = 'fls-disk-management-request:' + (document.documentElement.dataset.userId || 'admin');
 const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
 const uuid4 = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
 const wwn = value => typeof value === 'string' && /^(?:0x[a-f0-9]{16}|id:[a-f0-9]{64})$/.test(value);
 const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const names = {migrate:'Ana diske taşıma',prepare:'Eşleme diski hazırlama',sync:'Depo eşitleme'};
 const states = {queued:'Sırada',running:'Çalışıyor',succeeded:'Tamamlandı',failed:'Tamamlanamadı',rejected:'Reddedildi'};
 const failureCode = value => typeof value==='string'&&/^[a-z0-9_]{1,64}$/.test(value)?value:'';
 const terminalNotice = (job,prefix='İşlem') => job.status==='succeeded'?prefix+' tamamlandı.':prefix+' tamamlanamadı. Disk durumunu kontrol edin.'+(failureCode(job.error_code)?' Denetim kodu: '+failureCode(job.error_code)+'.':'');
 const reasons = {protected_disk:'Sistem ve ana depo diskleri korunur.',system_disk:'Sistem diski korunur.',depot_disk:'Ana depo diski korunur.',size_too_small:'Kapasitesi ana depo diskinden küçük.',too_small:'Kapasitesi ana depo diskinden küçük.',mounted:'Disk veya bir bölümü kullanımda.',disk_mounted:'Disk veya bir bölümü kullanımda.',swap_in_use:'Disk takas alanı olarak kullanılıyor.',active_holders:'Disk başka bir depolama biriminde kullanılıyor.',read_only:'Disk salt okunur.',identity_missing:'Disk kimliği doğrulanamadı.',in_use:'Disk kullanımda.'};
 let root=null,snapshot=null,observed=0,reading=false,writing=false,sequence=0,controller=null,lastRead=0,denied=false,pending=null,acknowledged=null,error='',notice='',dialog=null,preview=null,returnFocus=null,wasActive=false;
 const admin = () => !denied && document.documentElement.dataset.userRole === 'admin';
 const active = () => admin() && !document.hidden && root?.isConnected && !document.getElementById('view-settings')?.classList.contains('hidden') && document.querySelector('#settings-content [data-settings-tab="storage"][aria-selected="true"]');
 const instant = value => typeof value === 'string' && value ? new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(value)?value:value.replace(' ','T')+'Z').getTime() : NaN;
 const fresh = () => admin() && snapshot?.available === true && snapshot.fresh === true && observed>0 && Date.now()-observed<30000 && Date.now()-instant(snapshot.checked_at)>=-5000 && Date.now()-instant(snapshot.checked_at)<=45000;
 const busy = () => acknowledged || (['queued','running'].includes(snapshot?.active_job?.status)?snapshot.active_job:null);
 const workerBusy = () => ['preparing','syncing','migrating'].includes(snapshot?.status);
 const canWrite = () => !workerBusy() && fresh() && !reading && !writing && !pending && !busy();
 const protectedDisk = disk => disk && [snapshot?.system?.wwn,snapshot?.depot?.wwn].includes(disk.wwn);
 const eligible = disk => disk && disk.eligible === true && wwn(disk.wwn) && /^[a-f0-9]{64}$/.test(disk.token) && disk.reasons.length===0 && !protectedDisk(disk) && Number.isSafeInteger(disk.size_bytes) && (snapshot.mode==='system-root'||Number.isSafeInteger(snapshot?.depot?.size_bytes)&&disk.size_bytes>=snapshot.depot.size_bytes);
 const canPrepare = disk => canWrite() && (snapshot.mode==='system-root'?snapshot.can_migrate===true:snapshot.can_prepare===true) && !snapshot.mirror && eligible(disk);
 const canSync = () => canWrite() && snapshot.can_sync === true && !!snapshot.mirror && snapshot.mirror.present===true;
 const find = id => root?.querySelector('#'+id);
 const put = (id,value) => {const node=find(id);if(node.innerHTML!==value)node.innerHTML=value;};
 function bytes(value) {
  if(!Number.isSafeInteger(value)||value<0)return '—';
  const unit=value>=1099511627776?[1099511627776,'TiB']:value>=1073741824?[1073741824,'GiB']:value>=1048576?[1048576,'MiB']:[1,'B'];
  return (value/unit[0]).toLocaleString('tr-TR',{maximumFractionDigits:2})+' '+unit[1];
 }
 function time(value) {const at=instant(value);return Number.isNaN(at)?'—':new Intl.DateTimeFormat('tr-TR',{dateStyle:'medium',timeStyle:'short',timeZone:'Europe/Istanbul'}).format(at);}
 function validDisk(disk,candidate=false) {return disk===null || disk && typeof disk==='object' && (wwn(disk.wwn)||candidate&&disk.eligible===false&&disk.wwn==='') && typeof disk.serial==='string' && typeof disk.model==='string' && Number.isSafeInteger(disk.size_bytes) && disk.size_bytes>0;}
 function validJob(job) {return job && Number.isSafeInteger(job.id) && job.id>0 && uuid4(job.request_key) && Object.hasOwn(names,job.action) && Object.hasOwn(states,job.status);}
 function valid(value) {
  const unavailable=value?.available===false && value?.fresh===false;
  return value && value.schema===1 && (['system-root','hybrid'].includes(value.mode)||unavailable&&value.mode===null) && (uuid(value.boot_id)||unavailable&&value.boot_id===null) && (typeof value.checked_at==='string'&&!Number.isNaN(instant(value.checked_at))||unavailable&&value.checked_at===null) && typeof value.available==='boolean' && typeof value.fresh==='boolean' && typeof value.can_prepare==='boolean' && typeof value.can_sync==='boolean' && validDisk(value.system) && validDisk(value.depot) && validDisk(value.mirror) && Array.isArray(value.candidates) && value.candidates.every(disk=>disk!==null && validDisk(disk,true) && typeof disk.eligible==='boolean' && Array.isArray(disk.reasons) && disk.reasons.every(reason=>typeof reason==='string') && typeof disk.token==='string' && (/^[a-f0-9]{64}$/.test(disk.token)||disk.eligible===false&&disk.token==='')) && Array.isArray(value.jobs) && value.jobs.every(validJob) && (value.active_job===null || validJob(value.active_job));
 }
 function persist(value) {pending=value;try{if(value)sessionStorage.setItem(key,JSON.stringify(value));else sessionStorage.removeItem(key);}catch(_){/* The request identity remains pinned in memory. */}}
 try{
  const value=JSON.parse(sessionStorage.getItem(key)||'null');
  if(value && ['prepare','sync','migrate'].includes(value.action) && uuid4(value.request_key) && uuid(value.boot_id) && (value.action==='sync' || wwn(value.candidate_wwn) && /^[a-f0-9]{64}$/.test(value.inventory_token) && typeof value.disk_serial==='string' && typeof value.disk_model==='string' && Number.isSafeInteger(value.disk_size_bytes) && value.disk_size_bytes>0))pending=value;
 }catch(_){/* Saved state never triggers a POST. */}
 function card(title,disk,copy,empty='Yapılandırılmadı'){
  const state=!fresh()?'Durum doğrulanamadı':!disk?empty:disk.present===true?'Bağlı':disk.present===false?'Bağlı değil':'Durum doğrulanamadı';
  return '<article class="disk-role-card"><div class="disk-role-heading"><h3>'+esc(title)+'</h3><span class="tag '+(state==='Bağlı'?'pass':'medium')+'">'+esc(state)+'</span></div>'+
   (disk?'<strong>'+esc(disk.model)+'</strong><dl><div><dt>Seri numarası</dt><dd>'+esc(disk.serial)+'</dd></div><div><dt>Kapasite</dt><dd>'+esc(bytes(disk.size_bytes))+'</dd></div><div><dt>Disk kimliği</dt><dd class="disk-identity">'+esc(disk.wwn)+'</dd></div>'+(Number.isSafeInteger(disk.free_bytes)?'<div><dt>Boş alan</dt><dd>'+esc(bytes(disk.free_bytes))+'</dd></div>':'')+'</dl>':'')+'<p>'+copy+'</p></article>';
 }
 function layout(){
  if(!fresh())return '<p class="disk-empty">Dizinlerin bulunduğu disk, güncel envanter doğrulandıktan sonra gösterilir.</p>';
  if(snapshot.mode==='system-root')return '<div><h3>Sistem diski · tek disk düzeni</h3><p>Ubuntu, FLS, MariaDB, loglar ve yedekler sistem diskinde saklanır. Ayrı ana depo diski zorunlu değildir.</p><pre>/srv/fls-server/\n  raw/       Ham loglar\n  archive/   Arşivler ve damga belgeleri\n  metrics/   Sağlık ölçümleri\n  backups/   Yedek hazırlama alanı\n  db-dumps/  Günlük logsuz DB yedekleri\n/var/lib/fls-recovery-download/\n             İndirilebilir sistem yedekleri</pre><p>Geçici teslim kuyruğu: /srv/fls-server/queue · en fazla 10 GB.</p></div>';
  return '<div><h3>Sistem diski</h3><p>Ubuntu, FLS, MariaDB ve aranabilir indeks.</p><p>Geçici teslim kuyruğu: en fazla 10 GB.</p></div><div><h3>Ana depo · /srv/fls-storage</h3><pre>FLS-Logs/\n  raw/       Ham loglar\n  archive/   Arşivler ve damga belgeleri\n  metrics/   Sağlık ölçümleri\nFLS-Backups/\n  staging/   Yedek hazırlama alanı\n  published/ İndirilebilir sistem yedekleri\nDB-Dump/     Günlük logsuz DB yedekleri</pre></div>';
 }
 function render(){
  if(!root?.isConnected)return;
  root.hidden=!admin();if(!admin()){if(dialog?.open)dialog.close();return;}
  root.setAttribute('aria-busy',String(reading||writing));
  find('disk-management-refresh').disabled=reading||writing||!admin();
  find('disk-management-status').textContent=!admin()?'Yönetici oturumu gerekli.':reading?'Diskler kontrol ediliyor…':writing?'İstek kaydediliyor…':pending?'Önceki isteğin sonucu doğrulanmalı. Aynı istek kimliği korunuyor.':busy()?names[busy().action]+' · '+states[busy().status]:workerBusy()?(snapshot.status==='preparing'?'Eşleme diski hazırlanıyor…':'Ana depo eşitleniyor…'):!fresh()?'Güncel disk durumu alınamadı. Listeyi yenileyin.':'Disk rolleri doğrulandı.';
  const failure=error||(snapshot?.error_code?'Disk yönetimi denetimi tamamlanamadı. Listeyi yenileyin; disklerin bağlantı durumu henüz doğrulanamadı.'+(/^[a-z0-9_]{1,64}$/.test(snapshot.error_code)?' Denetim kodu: '+snapshot.error_code+'.':''):'');
  find('disk-management-error').textContent=failure;find('disk-management-error').hidden=!failure;
  find('disk-management-notice').textContent=notice;find('disk-management-notice').hidden=!notice;
  find('disk-management-replay').hidden=!pending;find('disk-management-replay').disabled=!fresh()||writing||reading||!admin();
  find('disk-management-replay').textContent=['prepare','migrate'].includes(pending?.action)?'Önceki disk hazırlama isteğini denetle':'Önceki eşitleme isteğini denetle';
  if(!snapshot){put('disk-role-cards','<p class="disk-empty">Disk envanteri henüz yüklenmedi.</p>');put('disk-layout-columns','<p class="disk-empty">Dizinlerin bulunduğu disk, güncel envanter doğrulandıktan sonra gösterilir.</p>');return;}
  put('disk-role-cards',card('Sistem diski',snapshot.system,'Ubuntu, FLS yazılımı, MariaDB ve aranabilir indeks bu diskte çalışır. Geçici teslim kuyruğu 10 GB ile sınırlıdır.')+
   card('Ana depo diski',snapshot.depot,snapshot.mode==='system-root'?'Şu anda loglar ve yedekler sistem diskinde. Yeni ikinci disk eklediğinizde mevcut kayıtlar bu ekrandan taşınabilir.':'Ham loglar, arşivler, ölçümler ve yedek dosyaları bu diskte saklanır.',snapshot.mode==='system-root'?'Sistem diskinde':'Yapılandırılmadı')+
   card('Eşleme diski · isteğe bağlı',snapshot.mirror,snapshot.mirror?(snapshot.mirror.present===false?'Eşleme diski şu anda bağlı değil. Yeniden bağlanıp doğrulanana kadar eşitleme yapılamaz.':'Ana deponun saatlik rsync kopyasıdır. Yön: ana depo → eşleme diski. Kaynakta silinen dosyalar sonraki eşitlemede bu kopyadan da silinir.'):'En az ana depo diski kapasitesinde üçüncü bir disk ekleyerek saatlik rsync kopyasını etkinleştirebilirsiniz.'));
  put('disk-layout-columns',layout());
  const candidates=snapshot.candidates.filter(disk=>!protectedDisk(disk));
  put('disk-candidates',!fresh()?'<p class="disk-empty">Ek disklerin uygunluğu doğrulanamadı. Listeyi yenileyin.</p>':snapshot.mirror?'<p class="disk-empty">Eşleme diski yapılandırılmış. Yeni bir disk hazırlama işlemi kapalıdır.</p>':candidates.length?candidates.map(disk=>
   '<article class="disk-candidate"><div><h4>'+esc(disk.model)+'</h4><p>Seri: <strong>'+esc(disk.serial)+'</strong> · '+esc(bytes(disk.size_bytes))+'</p><small class="disk-identity">'+esc(disk.wwn)+'</small><p>'+
   (eligible(disk)?(snapshot.mode==='system-root'?'Tek ext4 bölümle ana depo hazırlanır; mevcut loglar ve yedekler doğrulanarak taşınır.':'Tek ext4 bölümle eşleme diski olarak hazırlanabilir.'):esc(disk.reasons.map(reason=>reasons[reason]||'Bu disk eşleme için kullanılamıyor.').join(' ')||'Kapasitesi veya kullanım durumu uygun değil.'))+
   '</p></div><button type="button" class="button disk-destructive" data-disk-prepare="'+esc(disk.wwn)+'" '+(canPrepare(disk)?'':'disabled')+'>'+(snapshot.mode==='system-root'?'Ana disk hazırla ve kayıtları taşı':'Eşleme diski olarak hazırla')+'</button></article>').join(''):'<p class="disk-empty">Uygun ek disk bulunmuyor. Mevcut depolama düzeni çalışmaya devam eder.</p>');
  find('disk-management-sync').hidden=!snapshot.mirror;find('disk-management-sync').disabled=!canSync();
  const latest=snapshot.jobs.find(job=>job.status==='succeeded'),lastSync=snapshot.mirror?.last_sync_at||latest?.completed_at;
  find('disk-last-sync').textContent=snapshot.mirror?'Son başarılı eşitleme: '+time(lastSync)+' · Otomatik eşitleme: her saat.'+(['failed','unavailable'].includes(snapshot.mirror.last_sync_status)?' Son eşitleme denemesi tamamlanamadı.':''):'Otomatik eşitleme, üçüncü disk başarıyla hazırlandıktan sonra başlar.';
  const percent=Number.isFinite(snapshot.progress?.percent)&&snapshot.progress.percent>=0&&snapshot.progress.percent<=100?snapshot.progress.percent:null;
  find('disk-progress').hidden=!(busy()||workerBusy());
  find('disk-progress-text').textContent='İlk hazırlama ve kopyalama disklerdeki veri miktarına göre sürebilir.'+(percent!==null?' · %'+percent.toLocaleString('tr-TR',{maximumFractionDigits:1}):'');
  find('disk-progress-meter').removeAttribute('value');if(percent!==null)find('disk-progress-meter').value=percent;
  put('disk-management-history',snapshot.jobs.length?'<table><thead><tr><th>İşlem</th><th>Durum</th><th>Disk</th><th>Sonuç zamanı</th></tr></thead><tbody>'+snapshot.jobs.slice(0,6).map(job=>'<tr><td>'+esc(names[job.action])+'</td><td>'+esc(states[job.status])+(job.error_code?'<small>İşlem tamamlanamadı; güncel disk durumunu kontrol edin.'+(failureCode(job.error_code)?' Denetim kodu: '+esc(failureCode(job.error_code))+'.':'')+'</small>':'')+'</td><td>'+esc(job.disk_serial||'—')+'</td><td>'+esc(time(job.completed_at||job.started_at||job.requested_at))+'</td></tr>').join('')+'</tbody></table>':'<p class="disk-empty">Henüz disk hazırlama veya elle eşitleme isteği yok.</p>');
  find('disk-management-checked').textContent='Envanter kontrolü: '+time(snapshot.checked_at);
  updateDialog();
 }
 function mount(element){
  if(!admin()||!element?.isConnected)return;
  if(root!==element){
   root=element;root.innerHTML='<section class="panel disk-management-panel" aria-labelledby="disk-management-title"><div class="panel-heading"><div><h2 id="disk-management-title">Disk ve depolama</h2><p>Tek sistem diski veya ek ana depo ve isteğe bağlı eşleme diski.</p></div><button type="button" class="button" id="disk-management-refresh">Diskleri yenile</button></div><div class="disk-management-body"><p id="disk-management-status" role="status" aria-live="polite"></p><p id="disk-management-error" class="disk-management-error" role="alert" hidden></p><p id="disk-management-notice" class="disk-management-notice" role="status" hidden></p><button type="button" class="button" id="disk-management-replay" hidden></button><div id="disk-role-cards" class="disk-role-cards"></div><details class="disk-layout"><summary>Disklerde neler saklanır?</summary><div id="disk-layout-columns" class="disk-layout-columns"></div></details><section class="disk-mirror"><h3>Ek disk yönetimi</h3><p class="disk-copy-explanation">İlk kopyadan sonra her saat yalnız yeni veya değişen dosyalar aktarılır. Ana depoda silinen dosyalar eşleme diskinde de silinir. MariaDB ve sistem diskindeki geçici teslim kuyruğu bu eşlemenin dışında kalır.</p><div id="disk-candidates"></div><div class="disk-sync-actions"><p id="disk-last-sync"></p><button type="button" class="button primary" id="disk-management-sync" hidden>Şimdi eşitle</button></div><div id="disk-progress" class="disk-progress" role="status" hidden><progress id="disk-progress-meter" max="100"></progress><p id="disk-progress-text"></p></div></section><details class="disk-history"><summary>Son disk işlemleri</summary><div id="disk-management-history"></div></details><small id="disk-management-checked"></small></div></section>';
   find('disk-management-refresh').onclick=()=>{error='';refresh();};
   find('disk-management-sync').onclick=()=>request('sync');
   find('disk-management-replay').onclick=()=>['prepare','migrate'].includes(pending?.action)?openPrepare(null,true):request('sync',null,true);
   root.addEventListener('click',event=>{const button=event.target instanceof Element&&event.target.closest('[data-disk-prepare]');if(button&&!button.disabled)openPrepare(snapshot?.candidates.find(disk=>disk.wwn===button.dataset.diskPrepare));});
   render();
  }
  if(active()&&!reading&&!writing&&!snapshot)refresh();
 }
 function accept(value){
  if(!valid(value))throw new Error('Disk envanteri doğrulanamadı.');
  snapshot=value;observed=Date.now();
  if(acknowledged){const job=value.jobs.find(job=>job.request_key===acknowledged.request_key);if(job){acknowledged=['queued','running'].includes(job.status)?job:null;if(!acknowledged)notice=terminalNotice(job);}}
  if(pending){const job=value.jobs.find(job=>job.request_key===pending.request_key);if(job){acknowledged=['queued','running'].includes(job.status)?job:null;notice=['succeeded','failed','rejected'].includes(job.status)?terminalNotice(job,'Önceki işlem'):'Önceki istek sunucuda bulundu; işlem devam ediyor.';persist(null);}}
  render();
 }
 async function body(response){
  const value=await response.json();if(response.status===401||response.status===403)denied=true;
  if(!response.ok){const failure=new Error(typeof value?.error==='string'?value.error:'Disk işlemi tamamlanamadı.');failure.status=response.status;throw failure;}
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Disk yönetimi yanıtı okunamadı.');
  return value;
 }
 async function refresh(){
  if(!active()||reading||writing)return false;
  const mine=++sequence,abort=new AbortController();controller=abort;reading=true;lastRead=Date.now();render();const timer=setTimeout(()=>abort.abort(),12000);
  try{const response=await fetch('/api.php?route=disk_management',{credentials:'same-origin',cache:'no-store',signal:abort.signal}),value=await body(response);if(mine!==sequence)return false;accept(value);return true;}
  catch(failure){if(mine===sequence){observed=0;error=denied?'Yönetici oturumu doğrulanamadı. Sayfayı yeniden yükleyin.':'Disk durumu alınamadı. Listeyi yenileyebilirsiniz.';render();}return false;}
  finally{clearTimeout(timer);if(mine===sequence){reading=false;controller=null;render();}}
 }
 function ensureDialog(){
  if(dialog)return;
  dialog=document.createElement('dialog');dialog.id='disk-prepare-dialog';dialog.className='disk-confirm-dialog';dialog.setAttribute('aria-labelledby','disk-prepare-title');
  dialog.innerHTML='<form id="disk-prepare-form"><h2 id="disk-prepare-title">Eşleme diskini hazırla</h2><p class="disk-erase-warning">Seçilen diskteki TÜM VERİLER KALICI OLARAK SİLİNECEK.</p><div id="disk-prepare-identity"></div><p id="disk-prepare-description">Bu disk tek bir ext4 bölümle biçimlendirilecek ve ana deponun ilk kopyası alınacak. Başarılı hazırlamadan sonra saatlik rsync eşitlemesi başlayacak.</p><p id="disk-prepare-scope">Sistem diski ve ana depo bu işlemde değiştirilemez. İşlem yalnız aşağıda kimliği gösterilen üçüncü diske uygulanır.</p><label for="disk-prepare-confirmation">Diski kontrol ettiyseniz onaylamak için <strong>TAMAM</strong> yazın.<input id="disk-prepare-confirmation" name="confirmation" autocomplete="off" spellcheck="false" maxlength="5" required></label><p id="disk-prepare-validity" role="status"></p><div class="disk-dialog-actions"><button type="button" class="button" id="disk-prepare-cancel">Vazgeç</button><button type="submit" class="button disk-destructive" id="disk-prepare-submit" disabled>Diski sil ve eşlemeyi başlat</button></div></form>';
  document.body.append(dialog);
  dialog.querySelector('#disk-prepare-confirmation').oninput=updateDialog;
  dialog.querySelector('#disk-prepare-cancel').onclick=()=>dialog.close();
  dialog.addEventListener('close',()=>{dialog.querySelector('#disk-prepare-confirmation').value='';preview=null;returnFocus?.focus();});
  dialog.querySelector('form').onsubmit=event=>{event.preventDefault();if(dialog.querySelector('#disk-prepare-submit').disabled||!preview)return;const context={...preview};dialog.close();request(context.action||'prepare',context,context.replay===true);};
 }
 function dialogAllowed(){
  if(!preview||!fresh()||writing||reading||!active())return false;
  if(preview.replay)return pending?.request_key===preview.request_key;
  const disk=snapshot.candidates.find(disk=>disk.wwn===preview.wwn);
  return canPrepare(disk)&&snapshot.boot_id===preview.boot_id&&disk.token===preview.token&&disk.serial===preview.serial&&disk.model===preview.model&&disk.size_bytes===preview.size_bytes;
 }
 function updateDialog(){
  if(!dialog?.open)return;const allowed=dialogAllowed();
  dialog.querySelector('#disk-prepare-submit').disabled=!allowed||dialog.querySelector('#disk-prepare-confirmation').value!=='TAMAM';
  dialog.querySelector('#disk-prepare-validity').textContent=allowed?'Yalnız yukarıdaki disk silinecek.':'Envanter veya disk durumu değişti. Pencereyi kapatıp güncel listeyi yükleyin.';
 }
 function openPrepare(disk,replay=false){
  if(replay?!pending||!['prepare','migrate'].includes(pending.action)||!fresh()||writing:!canPrepare(disk))return;
  ensureDialog();returnFocus=document.activeElement;
  preview=replay?{...pending,replay:true,wwn:pending.candidate_wwn,serial:pending.disk_serial,model:pending.disk_model,size_bytes:pending.disk_size_bytes}:{...disk,action:snapshot.mode==='system-root'?'migrate':'prepare',boot_id:snapshot.boot_id,replay:false};
  dialog.querySelector('#disk-prepare-identity').innerHTML='<dl class="disk-confirm-identity"><div><dt>Model</dt><dd>'+esc(preview.model)+'</dd></div><div><dt>Seri numarası</dt><dd><strong>'+esc(preview.serial)+'</strong></dd></div><div><dt>Disk kimliği</dt><dd>'+esc(preview.wwn)+'</dd></div><div><dt>Toplam kapasite</dt><dd>'+esc(bytes(preview.size_bytes))+' · '+esc(preview.size_bytes.toLocaleString('tr-TR'))+' bayt</dd></div><div><dt>Yeni bölüm</dt><dd>Tek bölüm · ext4 · seçilen depolama rolü</dd></div></dl>';
  const migration=preview.action==='migrate';
  dialog.querySelector('#disk-prepare-title').textContent=migration?'İkinci diski ana depo yap ve kayıtları taşı':'Eşleme diskini hazırla';
  dialog.querySelector('#disk-prepare-description').textContent=migration?'Seçilen diskin tamamı silinip tek ext4 bölüm oluşturulacak. Mevcut ham loglar, arşivler, ölçümler, sistem yedekleri ve DB dump dosyaları yeni diske taşınarak SHA-256 ve dosya izinleriyle doğrulanacak. Taşıma boyunca log alımı ve ilgili işler duracak.':'Bu disk tek ext4 bölümle biçimlendirilecek; ana deponun kopyası alınacak ve saatlik rsync başlayacak.';
  dialog.querySelector('#disk-prepare-scope').textContent=migration?'Ubuntu, FLS, MariaDB ve dayanıklı alım kuyruğu sistem diskinde kalır. Eski kopya otomatik silinmez. Kesinti veya hata olursa işler duraklatılmış kalır; aynı silme otomatik tekrarlanmaz.':'Sistem diski ve mevcut ana depo korunur; yalnız seçilen ek disk silinir.';
  dialog.querySelector('#disk-prepare-submit').textContent=migration?'Diski sil ve mevcut kayıtları taşı':'Diski sil ve eşlemeyi başlat';
  dialog.querySelector('#disk-prepare-confirmation').value='';dialog.showModal();updateDialog();dialog.querySelector('#disk-prepare-cancel').focus();
 }
 async function request(action,context=null,replay=false){
  if(!active()||writing||!fresh()||replay&&(!pending||pending.action!==action)||!replay&&(['prepare','migrate'].includes(action)?!canPrepare(snapshot.candidates.find(disk=>disk.wwn===context?.wwn)):!canSync()))return;
  let descriptor,csrf;
  try{
   csrf=document.querySelector('meta[name="csrf-token"]')?.content;if(!csrf)throw new Error('Oturum doğrulaması bulunamadı. Sayfayı yeniden yükleyin.');
   if(replay)descriptor={...pending};
   else{
    if(!globalThis.crypto?.randomUUID)throw new Error('Güvenli istek kimliği üretilemedi. HTTPS bağlantısını kontrol edin.');
    descriptor={action,request_key:crypto.randomUUID(),boot_id:snapshot.boot_id};
    if(['prepare','migrate'].includes(action)){if(!context||context.boot_id!==snapshot.boot_id)return;const disk=snapshot.candidates.find(disk=>disk.wwn===context.wwn);if(!disk||disk.token!==context.token||disk.serial!==context.serial||disk.size_bytes!==context.size_bytes)return;Object.assign(descriptor,{candidate_wwn:context.wwn,inventory_token:context.token,disk_serial:context.serial,disk_model:context.model,disk_size_bytes:context.size_bytes});}
   }
  }catch(failure){error=failure.message;render();return;}
  sequence++;controller?.abort();controller=null;reading=false;writing=true;error='';notice='';persist(descriptor);render();
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),15000);
  try{
   const values={request_key:descriptor.request_key,boot_id:descriptor.boot_id};if(['prepare','migrate'].includes(action))Object.assign(values,{inventory_token:descriptor.inventory_token,candidate_wwn:descriptor.candidate_wwn,confirmation:'TAMAM'});
   const response=await fetch('/api.php?route='+(action==='migrate'?'prepare_primary_disk':action==='prepare'?'prepare_mirror_disk':'sync_mirror_disk'),{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf},body:new URLSearchParams(values),signal:abort.signal}),value=await body(response);
   if(value.saved!==true||!validJob(value.job)||value.job.request_key!==descriptor.request_key||value.job.action!==action)throw new Error('İsteğin kaydedildiği doğrulanamadı.');
   acknowledged=['queued','running'].includes(value.job.status)?value.job:null;persist(null);
   notice=['succeeded','failed','rejected'].includes(value.job.status)?terminalNotice(value.job):'İstek kaydedildi. İşlem sunucuda devam eder; bu sayfayı açık tutmanız gerekmez.';
  }catch(failure){
   if(Number.isInteger(failure.status)&&failure.status>=400&&failure.status<500)persist(null);
   error=denied?'Yönetici oturumu doğrulanamadı. Sayfayı yeniden yükleyin.':pending?'İsteğin sonucu doğrulanamadı. Yeni disk silme isteği gönderilmez. Önce listeyi yenileyin; gerekirse aynı istek kimliğini denetleyin.':failure.message||'Disk işlemi tamamlanamadı.';
  }finally{clearTimeout(timer);writing=false;render();await refresh();}
 }
 window.flsDiskManagementMount=mount;
 function discover(){const element=document.getElementById('disk-management-root');if(element&&admin())mount(element);if(root)root.hidden=!admin();const show=!!active();if(show&&!wasActive&&!reading&&!writing)refresh();wasActive=show;if(!show&&dialog?.open&&!writing)dialog.close();}
 new MutationObserver(discover).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','aria-selected','data-user-role']});
 document.addEventListener('visibilitychange',discover);
 setInterval(()=>{if(!active())return;updateDialog();render();if(!reading&&!writing&&Date.now()-lastRead>=(busy()||workerBusy()||pending?3000:10000))refresh();},1000);
 discover();
})();
