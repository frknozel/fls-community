'use strict';
let maintenanceData=null,maintenanceSaving=false,maintenanceReading=false,maintenanceReadSequence=0,maintenanceContextGeneration=0,maintenanceIntent=null,maintenanceTimer=null,maintenanceObservedAt=0,maintenanceRehearsal=false;
const maintenanceReadOnly=(d=maintenanceData)=>document.documentElement.dataset.recoveryRehearsal==='1'||maintenanceRehearsal||d?.rehearsal===true||d?.read_only===true;
const maintenanceStateNames={normal:'Log alımı açık',paused:'Log alımı durduruldu',pending:'İstek uygulanıyor',error:'İşlem başarısız',inactive:'Log alıcısı kapalı',unknown:'Durum doğrulanamıyor',stale:'Durum güncel değil',rehearsal:'Kurtarma provası'};
const maintenanceCollectorNames={active:'Çalışıyor',inactive:'Kapalı',activating:'Başlatılıyor',deactivating:'Durduruluyor',failed:'Başarısız',unknown:'Bilinmiyor'};
function maintenanceSafeState(d){if(maintenanceReadOnly(d))return 'rehearsal';if(d===maintenanceData&&maintenanceObservedAt&&Date.now()-maintenanceObservedAt>45000)return 'stale';return d?.fresh===true&&d?.available===true&&Object.hasOwn(maintenanceStateNames,d.state)?d.state:((d?.state==='stale')?'stale':'unknown');}
function maintenanceBannerText(d){
 const status=maintenanceSafeState(d),paused=d?.request?.requested_mode==='paused';
 if(status==='rehearsal')return 'Kurtarma provası: log alımı ve otomatik işler kapalı. Bu panel üretim sistemini etkinleştirmez.';
 if(status==='normal')return '';
 if(status==='paused')return 'Bu sunucudaki tüm FortiGate’lerin log alımı durduruldu. Yeni loglar alınmıyor; yönetici başlatana kadar kapalı kalır. Mevcut kayıtlar ve disk kuyruğu korunur.';
 if(status==='pending')return paused?'Log alımını durdurma isteği uygulanıyor. Alıcının kapandığı henüz doğrulanmadı.':'Log alımını başlatma isteği uygulanıyor. Alıcının çalıştığı henüz doğrulanmadı.';
 if(status==='inactive')return 'Log alıcısı beklenmedik biçimde kapalı. Otomatik başlatma yapılmaz; yönetici işlemi gerekir.';
 if(status==='error')return 'Log alımı için istenen durum uygulanamadı. Yönetici yeniden denemeden önce alıcının gerçek durumunu kontrol etmeli.';
 return paused?'Log alımını durdurma isteği kayıtlı; alıcının güncel durumu doğrulanamıyor.':'Log alımının güncel durumu doğrulanamıyor. Bakım kaydedicisi veya alıcı kontrol edilmeli.';
}
function maintenancePanel(d){
 if(document.documentElement.dataset.userRole!=='admin')return '';
 if(maintenanceReadOnly(d))return '<section id="maintenance-panel" class="panel maintenance-panel"><div class="panel-heading"><div><h2>Log alımı · kurtarma provası</h2><p>Kurtarma provası: log alımı ve otomatik işler kapalı.</p></div><span class="tag medium" role="status">Kurtarma provası</span></div><div class="maintenance-actions"><button type="button" class="button maintenance-stop" data-maintenance-mode="paused" disabled>Log alımını durdur</button><button type="button" class="button primary" data-maintenance-mode="normal" disabled>Log alımını başlat</button><button type="button" class="button" data-maintenance-refresh disabled>Durumu yenile</button></div><p class="maintenance-help">Bu panelden log alımı başlatılamaz. Kullanıcı ve cihaz ayarlarını inceleyebilirsiniz; ham loglar ve çalışma geçmişi geri yüklenmez.</p></section>';
 const status=maintenanceSafeState(d),r=d?.request||{},w=d?.worker||{},revision=Number.isInteger(r.revision)&&r.revision>0?r.revision:null,disabled=maintenanceSaving||revision===null;
 const stopDisabled=disabled||status==='paused'||status==='pending'&&r.requested_mode==='paused',startDisabled=disabled||status==='normal'||status==='pending'&&r.requested_mode==='normal';
 const retry=status==='error'||status==='inactive'||status==='stale';
 return `<section id="maintenance-panel" class="panel maintenance-panel"><div class="panel-heading"><div><h2>Log alımı · bakım modu</h2><p>Bakım modunda bu sunucudaki tüm FortiGate’lerin log alımı durdurulur. Arşivler ve indeksleyiciler çalışmaya devam eder.</p></div><span class="tag ${status==='normal'?'pass':status==='error'||status==='inactive'?'failed':'medium'}" role="status">${maintenanceStateNames[status]}</span></div><div class="maintenance-facts"><div><span>İstenen durum</span><b>${r.requested_mode==='paused'?'Durdur':r.requested_mode==='normal'?'Çalıştır':'Bilinmiyor'}</b><small>Son istek: ${esc(trTime(r.requested_at,true))}${r.requested_by?' · '+esc(r.requested_by):''}</small></div><div><span>Alıcının gerçek durumu</span><b>${esc(maintenanceCollectorNames[w.collector_state]||'Bilinmiyor')}</b><small>Başlatma engeli: ${w.marker_present===true?'Etkin':w.marker_present===false?'Yok':'Bilinmiyor'} · Son kontrol: ${esc(trTime(w.checked_at,true))}</small></div></div>${w.error_code?`<p class="maintenance-error">${esc(w.error_code)}</p>`:''}<div class="maintenance-actions"><button type="button" class="button maintenance-stop" data-maintenance-mode="paused" ${stopDisabled?'disabled':''}>${retry&&r.requested_mode==='paused'?'Durdurmayı yeniden dene':'Log alımını durdur'}</button><button type="button" class="button primary" data-maintenance-mode="normal" ${startDisabled?'disabled':''}>${retry&&r.requested_mode==='normal'?'Başlatmayı yeniden dene':'Log alımını başlat'}</button><button type="button" class="button" data-maintenance-refresh ${maintenanceReading||maintenanceSaving?'disabled':''}>${maintenanceReading?'Yenileniyor…':'Durumu yenile'}</button></div><p class="maintenance-help">Durdurma süresizdir; otomatik başlatma yoktur. Disk kuyruğu ve mevcut kayıtlar silinmez.</p></section>`;
}
function maintenanceRender(){
 let banner=document.getElementById('maintenance-banner');const anchor=document.getElementById('index-banner');
 if(!banner&&anchor){banner=document.createElement('div');banner.id='maintenance-banner';banner.className='maintenance-banner';banner.setAttribute('role','status');banner.setAttribute('aria-live','polite');anchor.before(banner);}
 if(banner){const text=maintenanceBannerText(maintenanceData);banner.textContent=text;banner.hidden=!text;banner.dataset.state=maintenanceSafeState(maintenanceData);}
 const panel=document.getElementById('maintenance-panel');if(panel){panel.outerHTML=maintenancePanel(maintenanceData);bindMaintenancePanel();}
 if(document.documentElement.dataset.userRole==='admin'){
  const text=document.getElementById('collector-text'),dot=document.getElementById('collector-dot'),status=maintenanceSafeState(maintenanceData);
  if(text)text.textContent=status==='rehearsal'?'Kurtarma provası · log alımı kapalı':status==='normal'?'Log alıcısı çalışıyor':status==='paused'?'Log alımı durduruldu':status==='pending'?'Alıcı isteği uygulanıyor':'Alıcı durumu doğrulanamıyor';if(dot){dot.classList.toggle('bad',status!=='normal'&&status!=='rehearsal');dot.style.backgroundColor=status==='rehearsal'?'var(--ui-muted)':'';}
 }
}
function maintenanceAccept(d){
 if(!d||typeof d!=='object'||Array.isArray(d))return;
 if(d.rehearsal===true||d.read_only===true){maintenanceRehearsal=true;maintenanceData=d;maintenanceContextChanged();maintenanceRender();return;}
 const incoming=d.request?.revision,current=maintenanceData?.request?.revision;
 if(Number.isInteger(current)&&!Number.isInteger(incoming)){maintenanceData={...maintenanceData,available:false,fresh:false,state:'unknown'};maintenanceObservedAt=Date.now();maintenanceRender();return;}
 if(Number.isInteger(current)&&incoming<current)return;
 if(incoming===current&&maintenanceData?.fresh&&d.fresh&&String(d.worker?.checked_at||'')<String(maintenanceData.worker?.checked_at||''))return;
 if(incoming===current&&maintenanceData?.request)d={...d,request:{...maintenanceData.request,...d.request}};
 maintenanceData=d;maintenanceObservedAt=Date.now();maintenanceRender();
}
async function maintenanceRefresh(){
 if(maintenanceReadOnly()){maintenanceRender();return;}if(maintenanceReading)return;
 const sequence=++maintenanceReadSequence;maintenanceReading=true;maintenanceRender();
 try{const d=await api('maintenance_status');if(sequence===maintenanceReadSequence)maintenanceAccept(d);}
 catch(error){if(sequence!==maintenanceReadSequence||error.name==='AbortError')return;maintenanceData={...(maintenanceData||{}),fresh:false,state:'unknown'};maintenanceRender();}
 finally{if(sequence===maintenanceReadSequence){maintenanceReading=false;maintenanceRender();}}
}
function maintenanceContextChanged(){maintenanceContextGeneration++;const dialog=document.getElementById('maintenance-dialog');if(dialog?.open)dialog.close();maintenanceIntent=null;}
function maintenanceCurrent(intent){return !maintenanceReadOnly()&&intent===maintenanceIntent&&intent.generation===maintenanceContextGeneration&&document.documentElement.dataset.userRole==='admin'&&String(state.fgDevice)===intent.device&&state.view===intent.view&&state.systemTab===intent.tab&&document.getElementById('maintenance-dialog')?.open;}
function maintenanceOpen(mode){
 if(maintenanceReadOnly()||maintenanceSaving||document.documentElement.dataset.userRole!=='admin'||!['paused','normal'].includes(mode))return;
 const revision=maintenanceData?.request?.revision;if(!Number.isInteger(revision)||revision<1)return;
 let dialog=document.getElementById('maintenance-dialog');if(!dialog){dialog=document.createElement('dialog');dialog.id='maintenance-dialog';dialog.className='maintenance-dialog';dialog.setAttribute('aria-labelledby','maintenance-dialog-title');document.body.append(dialog);dialog.addEventListener('cancel',event=>{if(maintenanceSaving)event.preventDefault();});dialog.addEventListener('close',()=>{if(dialog.open)return;maintenanceIntent=null;dialog.innerHTML='';});}
 const paused=mode==='paused';dialog.setAttribute('aria-describedby','maintenance-dialog-scope');maintenanceIntent={mode,revision,generation:++maintenanceContextGeneration,view:state.view,tab:state.systemTab,device:String(state.fgDevice)};
 dialog.innerHTML=`<h2 id="maintenance-dialog-title">${paused?'Log alımı durdurulsun mu?':'Log alımı başlatılsın mı?'}</h2><span class="soft-tag maintenance-scope">Sunucu genelinde · tüm FortiGate’ler</span><p id="maintenance-dialog-scope">${paused?'Bu sunucudaki tüm FortiGate’lerin log alımı durdurulur. Alıcı siz başlatana kadar kapalı kalır. Mevcut kayıtlar ve disk kuyruğu korunur.':'Bu sunucudaki tüm FortiGate’ler için yeni bir başlatma isteği kaydedilir. Çalıştığı arka plan kaydedicisi tarafından doğrulanınca durum güncellenir.'}</p>${paused?'<p class="maintenance-risk">FortiGate’in kesinti sırasında oluşan yeni logları sonradan yeniden göndermesi garanti değildir. Bu aralıkta log kaybı oluşabilir.</p><label class="maintenance-consent"><input type="checkbox" id="maintenance-risk-consent"><span>Yeni logların sonradan gelmesinin garanti olmadığını kabul ediyorum.</span></label>':''}<p class="maintenance-dialog-error" id="maintenance-dialog-error" role="alert" hidden></p><div class="maintenance-dialog-actions"><button type="button" class="button" id="maintenance-cancel" autofocus>Vazgeç</button><button type="button" class="button ${paused?'maintenance-stop':'primary'}" id="maintenance-confirm" ${paused?'disabled':''}>${paused?'Log alımını durdur':'Log alımını başlat'}</button></div>`;
 dialog.querySelector('#maintenance-cancel').onclick=()=>{if(!maintenanceSaving)dialog.close();};const consent=dialog.querySelector('#maintenance-risk-consent');if(consent)consent.onchange=()=>{dialog.querySelector('#maintenance-confirm').disabled=!consent.checked;};dialog.querySelector('#maintenance-confirm').onclick=()=>maintenanceSubmit(maintenanceIntent);dialog.showModal();dialog.querySelector('#maintenance-cancel').focus();
}
async function maintenanceSubmit(intent){
 if(maintenanceSaving||!intent||!maintenanceCurrent(intent)||intent.mode==='paused'&&!document.getElementById('maintenance-risk-consent')?.checked)return;
 maintenanceSaving=true;const dialog=document.getElementById('maintenance-dialog'),confirm=dialog.querySelector('#maintenance-confirm'),cancel=dialog.querySelector('#maintenance-cancel'),error=dialog.querySelector('#maintenance-dialog-error');confirm.disabled=true;confirm.textContent='İstek kaydediliyor…';cancel.disabled=true;const consent=dialog.querySelector('#maintenance-risk-consent');if(consent)consent.disabled=true;error.hidden=true;
 try{
  const response=await fetch('/api.php?route=save_maintenance',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content},body:new URLSearchParams({requested_mode:intent.mode,revision:String(intent.revision)})});
  let d;try{d=await response.json();}catch(e){throw new Error('İstek sonucu doğrulanamadı. Durumu yenilemeden tekrar göndermeyin.');}
  if(!maintenanceCurrent(intent))return;
  if(!response.ok){if(response.status===409&&d.maintenance)maintenanceAccept(d.maintenance);throw new Error(typeof d.error==='string'?d.error:'İstek kaydedilemedi. Güncel durumu kontrol edin.');}
  maintenanceAccept(d.maintenance);dialog.close();toast(intent.mode==='paused'?'Durdurma isteği kaydedildi.':'Başlatma isteği kaydedildi.');
 }catch(e){if(maintenanceCurrent(intent)){error.textContent=e.message||'İstek sonucu doğrulanamadı. Durumu kontrol edin.';error.hidden=false;}}
 finally{maintenanceSaving=false;if(dialog.open){cancel.disabled=false;confirm.disabled=true;confirm.textContent=intent.mode==='paused'?'Log alımını durdur':'Log alımını başlat';}maintenanceRender();maintenanceRefresh();}
}
function bindMaintenancePanel(){const refresh=document.querySelector('[data-maintenance-refresh]');if(refresh)refresh.onclick=()=>maintenanceRefresh();for(const button of document.querySelectorAll('[data-maintenance-mode]'))button.onclick=()=>maintenanceOpen(button.dataset.maintenanceMode);}
function bindMaintenance(){
 bindMaintenancePanel();maintenanceRender();
 if(maintenanceTimer===null)maintenanceTimer=setInterval(()=>{if(!document.hidden)maintenanceRefresh();},10000);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)maintenanceRefresh();});
}
