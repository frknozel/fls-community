'use strict';
let managementData=null,managementSaving=false,managementFocus=null,managementConnections=[];
const managementSectionInfo={
 connections:{description:'Bağlantılar, anahtarlar ve kurulum',scope:'Cihaz bazında',detail:'Seçtiğiniz FortiGate’in bağlantısını ve API anahtarlarını yönetin. Buradaki cihaz seçimi, raporlarda incelediğiniz cihazı değiştirmez.'},
 users:{description:'Hesaplar, roller ve cihaz erişimi',scope:'Hesap ve erişim',detail:'Kullanıcı ekleyin, rolünü belirleyin ve inceleyebileceği FortiGate’leri seçin. Yeni hesaplara cihaz erişimi ayrıca atanır.'},
 archive:{description:'Saatlik paketler ve harici hedefler',scope:'Sunucu genelinde',detail:'Saatlik paketleme ve harici yedekleme hedefleri bu sunucudaki tüm FortiGate’lerin kayıtlarını kapsayabilir. Üstteki cihaz ve tarih seçimi bu ayarları sınırlamaz.'},
 storage:{description:'Sistem diski, ek ana depo ve isteğe bağlı eşleme',scope:'Sunucu genelinde',detail:'Tek diskle başlayabilir, ikinci diski eklediğinizde kayıtları ana depoya taşıyabilirsiniz. Ayrı ana depo hazırlandıktan sonra en az onun kapasitesinde üçüncü bir diskle saatlik rsync kopyası oluşturabilirsiniz.'},
 product:{description:'Lisans, saklama ve arşiv kopyaları',scope:'Kurulum genelinde',detail:'Lisansı, veri saklama sürelerini ve ayrıntılı arşiv kopyalarını inceleyin. Bu ayarlar seçili cihazdan ve rapor tarih aralığından bağımsızdır.'}
};
const managementCheckNames={untested:'Henüz sınanmadı',pending:'Sınama bekleniyor',ok:'Bağlantı doğrulandı',error:'Bağlantı kontrol edilmeli'};
const managementErrorNames={http_401:'Anahtar kabul edilmedi',http_403:'Trusted-host veya okuma yetkisi yetersiz',tls:'TLS sertifikası doğrulanamadı',device_scope:'Seri numarası / VDOM eşleşmiyor',connection_or_json:'HTTPS bağlantısı veya JSON yanıtı alınamadı',credential:'Anahtar kasadan açılamadı',json:'JSON yanıtı bekleniyordu',api_status:'API başarı durumu bildirmedi',response_limit:'Yanıt boyutu sınırı aşıldı'};
async function managementPost(route,values){
 const response=await fetch('/api.php?route='+route,{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content},body:new URLSearchParams(values)});
 const data=await response.json();if(!response.ok){const error=new Error(data.error||'İşlem tamamlanamadı.');error.status=response.status;throw error;}return data;
}
function managementField(label,name,value='',type='text',extra=''){
 return `<label>${esc(label)}<input name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;
}
function managementSelect(label,name,options,value){return `<label>${esc(label)}<select name="${name}">${options.map(([v,l])=>`<option value="${esc(v)}" ${String(v)===String(value)?'selected':''}>${esc(l)}</option>`).join('')}</select></label>`;}
function managementDevice(id){return managementData?.devices?.find(device=>String(device.id)===String(id));}
function managementDeviceKeys(id){return (managementData?.credentials||[]).filter(key=>String(key.connection_id)===String(id));}
function managementDeviceTarget(device){return `<div class="management-target"><span>Seçili FortiGate</span><strong>${esc(device.name)}</strong><small>${esc(device.serial)} · VDOM ${esc(device.vdom)}</small></div>`;}
function managementLastKeyMessage(key){
 const device=managementDevice(key.connection_id);
 return Number(device?.enabled)&&Number(key.enabled)&&managementDeviceKeys(key.connection_id).filter(k=>Number(k.enabled)).length<=1?'Bu cihazın tek etkin API anahtarı. Önce başka bir anahtar ekleyip etkinleştirin veya bağlantıyı devre dışı bırakın.':'';
}
function managementDialog(kind,item=null,connection=null){
 if(managementSaving)return;
 const dialog=$('#management-dialog'),title=$('#management-dialog-title'),form=$('#management-form');managementFocus=document.activeElement;form.dataset.kind=kind;
 let fields='',advanced='',help='',context='';
 if(kind==='connection'){
  title.textContent=item?'FortiGate bağlantısını düzenle':'FortiGate ekle';
  if(item)context=managementDeviceTarget(item);
  fields=managementField('Görünen ad','name',item?.name||'','text','required maxlength="100" placeholder="Örn. Merkez · FortiGate 50G"')+managementField('FortiGate seri numarası','serial',item?.serial||'','text',`required maxlength="40" ${item?'readonly':''}`)+managementField('VDOM','vdom',item?.vdom||'root','text',`required maxlength="64" ${item?'readonly':''}`)+managementField('TLS alan adı · URL / port olmadan','hostname',item?.hostname||'','text','required maxlength="253" placeholder="fg.sirketiniz.com"')+managementField('Bağlanılacak IP','connect_ip',item?.connect_ip||'','text','required maxlength="45" placeholder="192.0.2.1"')+managementField('HTTPS portu','port',item?.port||443,'number','required min="1" max="65535"')+managementSelect('Bağlantı durumu','enabled',[['0','Hazırlık / devre dışı'],['1','Etkin']],item?.enabled??0);
  advanced=managementField('Sunucunun çıkış IP’si · isteğe bağlı','source_ip',item?.source_ip||'','text','maxlength="45"')+managementSelect('Varsayılan FortiGate','is_default',[['0','Hayır'],['1','Evet']],item?.is_default??0);
  help='Yeni cihazı hazırlık durumunda kaydedin; ardından API anahtarını ekleyip sınayın ve bağlantıyı etkinleştirin. Seri numarası ve VDOM, doğru cihaza bağlanıldığını doğrular.';
 }else if(kind==='credential'||kind==='delete_credential'){
  const device=managementDevice(connection||item?.connection_id);if(!device){toast('Cihaz listesi değişti. Sayfayı yenileyin.');return;}
  context=managementDeviceTarget(device);
  fields=`<input type="hidden" name="connection_id" value="${esc(device.id)}">`;
  if(kind==='delete_credential'){
   title.textContent='API anahtarını sil';
   fields+=`<div class="management-delete-copy"><p><strong>${esc(item.name)}</strong> anahtarı FLS’den silinsin mi?</p><p>Bu işlem anahtarı FortiGate üzerinde iptal etmez.</p></div>`;
  }else{
   title.textContent=item?'API anahtarını düzenle':'API anahtarı ekle';
   fields+=managementField('Anahtar etiketi','name',item?.name||'','text','required maxlength="100" placeholder="Örn. Salt okuma anahtarı"')+managementField(item?'Yeni anahtar · boş bırakırsanız korunur':'FortiGate API anahtarı','token','','password',`autocomplete="new-password" maxlength="512" ${item?'':'required'}`)+managementSelect('Kullanım amacı','purpose',[['both','Canlı durum + policy / profiller'],['live','Canlı durum'],['config','Policy / profiller']],item?.purpose||'both')+managementSelect('FLS’de kullanım','enabled',[['1','Etkin'],['0','Devre dışı']],item?.enabled??1);
   advanced=managementField('Deneme önceliği · küçük sayı önce','priority',item?.priority??100,'number','required min="1" max="1000"');
   help='Anahtar yalnız yukarıdaki cihaza eklenir, şifreli saklanır ve geri gösterilmez. FortiGate API hesabını salt okuma yetkisiyle ve FLS sunucusunun IP’sine sınırlı oluşturun.';
  }
 }else if(kind==='user'){
  title.textContent=item?'Kullanıcı hesabını düzenle':'Kullanıcı ekle';
  fields=managementField('Kullanıcı adı','username',item?.username||'','text',`required minlength="3" maxlength="64" autocomplete="off" ${item?'readonly':''}`)+managementField('Ad soyad / görünen ad','display_name',item?.display_name||'','text','maxlength="100"')+managementSelect('Rol','role',[['analyst','Analist'],['admin','Yönetici']],item?.role||'analyst')+managementSelect('Hesap durumu','enabled',[['1','Etkin'],['0','Devre dışı']],item?.enabled??1);
  if(!item)fields+=managementField('İlk giriş parolası','password','','password','required minlength="14" maxlength="256" autocomplete="new-password"');
  fields+=`<fieldset class="management-access"><legend>Erişebileceği FortiGate’ler</legend><p>Log, policy, profil ve canlı durum erişimi. Boş bırakırsanız bu hesap hiçbir cihazı inceleyemez.</p><div class="management-access-list">${managementData.devices.map(d=>`<label class="management-access-choice"><input type="checkbox" name="device_access" value="${d.id}" ${(item?.device_ids||[]).map(Number).includes(Number(d.id))?'checked':''}><span><strong>${esc(d.name)}</strong><small>${esc(d.serial)} · ${esc(d.vdom)}${Number(d.enabled)?'':' · devre dışı'}</small></span></label>`).join('')||'<p>Önce bir FortiGate bağlantısı ekleyin.</p>'}</div></fieldset>`;
  help='Atamalar yönetici hesaplarının inceleme erişimi için de geçerlidir. Yöneticiler tüm bağlantıları ve kullanıcı atamalarını yönetebilir. Yeni cihazlar kendiliğinden erişim vermez. Yeni hesap ilk girişte parolasını değiştirir. Rol / durum değişikliği açık oturumları kapatır.';

 }else{
  title.textContent='Parolayı sıfırla · '+item.username;fields=managementField('Geçici parola','password','','password','required minlength="14" maxlength="256" autocomplete="new-password"');help='Bu hesabın tüm oturumları kapanır. Kullanıcı, ilk girişte bu geçici parolayı değiştirmelidir.';
 }
 const deleting=kind==='delete_credential';
 form.innerHTML=`<input type="hidden" name="id" value="${esc(item?.id||'')}"><input type="hidden" name="revision" value="${esc(item?.revision??'')}">${context}<div class="management-fields">${fields}</div>${advanced?`<details class="management-advanced"><summary>Gelişmiş seçenekler</summary><div class="management-fields">${advanced}</div></details>`:''}${help?`<p class="management-help">${esc(help)}</p>`:''}<p id="management-error" class="management-error" role="alert"></p><button type="button" class="text-button" id="management-reload" hidden>Güncel listeyi yükle</button><div class="management-actions"><button type="button" class="button" data-management-cancel ${deleting?'autofocus':''}>Vazgeç</button><button type="submit" class="button ${deleting?'management-danger':'primary'}" ${deleting?'data-management-delete-confirm':''}>${deleting?'Anahtarı sil':'Kaydet'}</button></div>`;
 form.querySelector('[data-management-cancel]').onclick=()=>{if(!managementSaving)dialog.close();};
 $('#management-reload').onclick=async()=>{if(managementSaving)return;dialog.close();await load();};
 dialog.showModal();(deleting?form.querySelector('[data-management-cancel]'):form.querySelector('input:not([type=hidden]):not([readonly])'))?.focus();
}
function managementCredentialRow(key){
 const status=key.check_status,detail=key.check_code?(managementErrorNames[key.check_code]||'Kontrol başarısız: '+key.check_code):'',enabled=Number(key.enabled);
 return `<article class="management-key" data-credential-id="${key.id}"><div class="management-key-copy"><div class="management-key-title"><strong>${esc(key.name)}</strong><span class="tag ${enabled?'info':'deny'}">${enabled?'Etkin':'Devre dışı'}</span></div><small>${esc({both:'Canlı durum + policy / profiller',live:'Canlı durum',config:'Policy / profiller'}[key.purpose]||key.purpose)}</small><span class="tag ${status==='ok'?'pass':status==='error'?'failed':'medium'}">${esc(managementCheckNames[status]||status)}</span>${detail?`<small>${esc(detail)}</small>`:''}<small>${key.checked_at?'Son sınama '+esc(trTime(key.checked_at,true)):'Bağlantı henüz sınanmadı'}${key.last_used_at?' · Son kullanım '+esc(trTime(key.last_used_at,true)):''}</small><details class="management-key-details"><summary>Anahtar bilgileri</summary><small>Öncelik ${esc(key.priority)} · Kimlik ${esc(key.fingerprint)}</small></details></div><div class="management-row-actions"><button class="button" data-key-test="${key.id}" ${status==='pending'?'disabled':''}>${status==='pending'?'Bekleniyor…':'Sına'}</button><button class="button" data-key-edit="${key.id}">Düzenle</button><button class="button" data-key-toggle="${key.id}">${enabled?'Devre dışı bırak':'Etkinleştir'}</button><button class="text-button management-danger" data-key-delete="${key.id}">Sil</button></div></article>`;
}
function managementSelectDevice(id,tab='keys',push=true){
 if(managementSaving||onboardingBusy)return;
 if(!managementDevice(id))return;
 state.settingsDevice=String(id);state.settingsDeviceTab=tab;state.setupDevice=tab==='setup'?String(id):'';state.settingsTab='connections';onboardingDirty=false;
 syncUrl(push?'push':'replace');renderManagement(managementData);
}
function managementDeviceList(devices,selected){
 return `<aside class="management-device-list" aria-label="Yönetilecek FortiGate"><label class="management-device-picker">FortiGate seçin<select id="settings-device-select">${devices.map(device=>`<option value="${device.id}" ${String(device.id)===String(selected)?'selected':''}>${esc(device.name)} · ${esc(device.connect_ip)}</option>`).join('')}</select></label><div class="management-device-buttons">${devices.map(device=>{
  const keys=managementDeviceKeys(device.id),active=String(device.id)===String(selected);
  return `<button type="button" class="management-device-choice ${active?'is-selected':''}" data-settings-device="${device.id}" aria-pressed="${active}"><span class="management-device-choice-title"><strong>${esc(device.name)}</strong><span class="tag ${Number(device.enabled)?'pass':'medium'}">${Number(device.enabled)?'Etkin':'Hazırlık'}</span></span><span>${esc(device.connect_ip)}:${esc(device.port)}</span><small>${esc(device.serial)} · ${esc(device.vdom)}</small><small>${keys.length} anahtar · ${keys.filter(key=>Number(key.enabled)).length} etkin${Number(device.is_default)?' · Varsayılan':''}</small></button>`;
 }).join('')}</div></aside>`;
}
function managementConnectionPanel(device){
 const facts=[['Seri numarası',device.serial],['VDOM',device.vdom],['Bağlantı adresi',device.connect_ip+':'+device.port],['TLS alan adı',device.hostname],['Bağlantı durumu',Number(device.enabled)?'Etkin':'Hazırlık / devre dışı'],['Varsayılan cihaz',Number(device.is_default)?'Evet':'Hayır']];
 return `<section class="management-connection-panel"><div class="management-section-title"><div><h4>Bağlantı ayarları</h4><p class="management-help">Cihaz adresini ve bağlantının etkin olup olmadığını buradan değiştirin.</p></div><button class="button primary" data-connection-edit="${device.id}">Bağlantıyı düzenle</button></div><dl class="management-device-facts">${facts.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><details class="management-advanced"><summary>Gelişmiş bağlantı bilgileri</summary><p class="management-help">Sunucunun çıkış IP’si: ${esc(device.source_ip||'Otomatik')}</p></details>${managementConnections.some(item=>String(item.id)===String(device.id))?`<button class="button" data-device-live="${device.id}">Bu cihazın canlı durumunu aç ↗</button>`:''}</section>`;
}
function managementConnectionsPanel(data){
 const requested=state.settingsDevice||state.setupDevice,device=data.devices.find(d=>String(d.id)===String(requested))||data.devices[0];
 const tab=['keys','connection','setup'].includes(state.settingsDeviceTab)?state.settingsDeviceTab:'keys';
 state.settingsDevice=device?String(device.id):'';state.settingsDeviceTab=tab;state.setupDevice=device&&tab==='setup'?String(device.id):'';
 const toolbar=`<div class="section-heading management-connections-heading"><div><h2>FortiGate’ler ve API anahtarları <span class="count-tag">${data.devices.length}/${data.limits?.devices||16}</span></h2><p class="management-help">Cihazı seçin, API anahtarlarını yönetin ve bağlantısını doğrulayın.</p></div><button type="button" class="button primary" data-connection-new>+ FortiGate ekle</button></div>`;
 if(!device)return toolbar+`<section class="panel management-device-empty"><h3>İlk FortiGate’inizi ekleyin</h3><p>Önce cihaz bilgilerini kaydedin, ardından o cihaza ait API anahtarını ekleyin.</p></section>`;
 const keys=managementDeviceKeys(device.id),labels={keys:'API anahtarları',connection:'Bağlantı ayarları',setup:'Kurulum ve doğrulama'};
 const header=`<div class="management-detail-heading"><div><div class="management-detail-title"><h3>${esc(device.name)}</h3><span class="tag ${Number(device.enabled)?'pass':'medium'}">${Number(device.enabled)?'Etkin':'Hazırlık / devre dışı'}</span>${Number(device.is_default)?'<span class="soft-tag">Varsayılan</span>':''}</div><p>${esc(device.connect_ip)}:${esc(device.port)} · ${esc(device.serial)} · VDOM ${esc(device.vdom)}</p></div><button class="button primary" data-key-new="${device.id}">+ API anahtarı</button></div>`;
 const tabs=`<div class="management-device-tabs" role="tablist" aria-label="Seçili cihaz ayarları">${Object.entries(labels).map(([key,label])=>`<button type="button" role="tab" id="settings-device-tab-${key}" aria-controls="settings-device-panel" aria-selected="${tab===key}" tabindex="${tab===key?0:-1}" data-settings-device-tab="${key}" ${key==='setup'?`data-setup-open="${device.id}"`:''}>${label}</button>`).join('')}</div>`;
 const content=tab==='keys'?`<section class="management-keys-panel"><div class="management-section-title"><div><h4>API anahtarları <span class="count-tag">${keys.length}/${data.limits?.keys_per_device||8}</span></h4><p class="management-help">Bu liste yalnız ${esc(device.name)} cihazına aittir. Anahtarı devre dışı bırakmak veya silmek FortiGate üzerindeki anahtarı iptal etmez.</p></div></div>${keys.length?`<div class="management-keys">${keys.map(managementCredentialRow).join('')}</div>`:`<div class="management-key-empty"><strong>Bu cihaz için ilk API anahtarını ekleyin</strong><p>Cihaz bilgileri kaydedildi. Yukarıdaki “+ API anahtarı” düğmesiyle bağlantıyı tamamlayın.</p></div>`}</section>`:tab==='connection'?managementConnectionPanel(device):'<div id="management-setup-content"><div class="loading-state">Kurulum denetleniyor…</div></div>';
 const access=managementConnections.some(item=>String(item.id)===String(device.id))?'':`<div class="management-access-note"><p>Bu cihazı incelemek için hesabınıza cihaz erişimi atanmalı.</p><button type="button" class="text-button" data-manage-device-access>Kullanıcı erişimlerini yönet →</button></div>`;
 return toolbar+`<div class="management-workspace">${managementDeviceList(data.devices,device.id)}<article class="panel management-device-detail" id="management-device-detail" data-device-id="${device.id}">${header}${access}${tabs}<p id="management-key-error" class="management-error" role="alert"></p><button type="button" class="text-button" data-management-list-reload hidden>Güncel listeyi yükle</button><div id="settings-device-panel" role="tabpanel" aria-labelledby="settings-device-tab-${tab}">${content}</div></article></div>`;
}
function managementUsersPanel(data){
 return `<div class="section-heading"><div><h2>Kullanıcı hesapları</h2><p class="management-help">Yeni hesapların cihaz erişimi yoktur. Atamalar sonraki istekte geçerli olur.</p></div><button class="button primary" data-user-new>+ Kullanıcı ekle</button></div><section class="panel"><div class="table-wrap"><table class="management-user-table"><thead><tr><th>Hesap</th><th>Rol</th><th>FortiGate erişimi</th><th>Durum</th><th></th></tr></thead><tbody>${data.users.map(user=>`<tr><td><strong>${esc(user.display_name||user.username)}</strong><small>${esc(user.username)}</small></td><td>${user.role==='admin'?'Yönetici':'Analist'}</td><td><div class="management-grants">${(user.device_ids||[]).map(id=>`<span class="soft-tag">${esc(data.devices.find(device=>Number(device.id)===Number(id))?.name||'Cihaz kaldırılmış')}</span>`).join('')||'<span class="tag medium">Erişim atanmamış</span>'}</div></td><td><span class="tag ${Number(user.enabled)?'pass':'deny'}">${Number(user.enabled)?'Etkin':'Devre dışı'}</span>${Number(user.must_change)?'<small>İlk girişte parola değiştirecek</small>':''}</td><td><div class="management-row-actions"><button class="button" data-user-edit="${user.id}">Düzenle</button><button class="text-button" data-user-reset="${user.id}">Parola sıfırla</button></div></td></tr>`).join('')}</tbody></table></div></section>`;
}
function managementKeyError(message,reload=false){
 const error=$('#management-key-error');if(error)error.textContent=message;const button=$('[data-management-list-reload]');if(button)button.hidden=!reload;
}
async function managementToggleCredential(key,button){
 if(managementSaving)return;
 const guard=managementLastKeyMessage(key);if(guard){managementKeyError(guard);return;}
 managementSaving=true;button.disabled=true;managementKeyError('');
 try{await managementPost('set_credential_enabled',{id:key.id,connection_id:key.connection_id,revision:key.revision,enabled:Number(key.enabled)?'0':'1'});toast(Number(key.enabled)?'Anahtar devre dışı bırakıldı.':'Anahtar etkinleştirildi.');await load();}
 catch(error){managementKeyError(error.message,error.status===409);}
 finally{managementSaving=false;if(button.isConnected)button.disabled=false;}
}
function renderManagement(data){
 managementData=data;const root=$('#settings-content');
 const profile=`<section class="panel management-account"><div><h2>${esc(data.user.display_name||data.user.username)}</h2><p>${esc(data.user.username)} · ${data.admin?'Yönetici':'Analist'}</p></div><a class="button" href="/?account=1">Parolamı değiştir</a></section>`;
 if(!data.admin){root.innerHTML=profile+'<div class="info-strip"><p>Cihaz, API anahtarı ve kullanıcı yönetimi yönetici yetkisi gerektirir.</p></div>';return;}
 const tab=Object.hasOwn(managementSectionInfo,state.settingsTab)?state.settingsTab:'connections',tabs={connections:'FortiGate’ler ve API anahtarları',users:'Kullanıcı hesapları',archive:'Arşiv ve yedekleme',storage:'Disk ve depolama',product:'Ürün ve saklama'};
 root.innerHTML=profile+`<div class="workspace-tabs management-section-tabs" role="tablist" aria-label="Ayar bölümü">${Object.entries(tabs).map(([key,label])=>`<button type="button" role="tab" id="settings-tab-${key}" aria-controls="management-${key}" data-settings-tab="${key}" tabindex="${tab===key?0:-1}" aria-selected="${tab===key}" aria-label="${esc(label)}"><span>${esc(label)}</span><small>${esc(managementSectionInfo[key].description)}</small></button>`).join('')}</div><aside class="management-section-context" aria-label="Bölüm kapsamı"><span class="soft-tag">${esc(managementSectionInfo[tab].scope)}</span><p>${esc(managementSectionInfo[tab].detail)}</p></aside><div id="management-connections" role="tabpanel" aria-labelledby="settings-tab-connections" ${tab!=='connections'?'hidden':''}>${managementConnectionsPanel(data)}</div><div id="management-users" role="tabpanel" aria-labelledby="settings-tab-users" ${tab!=='users'?'hidden':''}>${managementUsersPanel(data)}</div><div id="management-archive" role="tabpanel" aria-labelledby="settings-tab-archive" ${tab!=='archive'?'hidden':''}><div class="archive-management-root">Yükleniyor…</div></div><div id="management-storage" role="tabpanel" aria-labelledby="settings-tab-storage" ${tab!=='storage'?'hidden':''}><div id="disk-management-root"></div></div><div id="management-product" role="tabpanel" aria-labelledby="settings-tab-product" ${tab!=='product'?'hidden':''}><div id="product-settings-content">Yükleniyor…</div></div>`;
 if(state.view==='settings')syncUrl();
 if(tab==='connections'&&state.settingsDeviceTab==='setup'&&state.setupDevice)onboardingRefresh(root.querySelector('#management-setup-content'));
 if(tab==='product')loadProductSettings(root.querySelector('#product-settings-content'));
 if(tab==='archive')managementLoadArchive(root.querySelector('.archive-management-root'));
 if(tab==='storage'&&typeof window.flsDiskManagementMount==='function')window.flsDiskManagementMount(root.querySelector('#disk-management-root'));
 root.querySelectorAll('[data-settings-tab]').forEach(button=>{
  button.onclick=()=>{if(managementSaving||onboardingBusy)return;state.settingsTab=button.dataset.settingsTab;syncUrl('push');renderManagement(data);root.querySelector('[data-settings-tab="'+state.settingsTab+'"]').focus();};
  button.onkeydown=event=>managementTabKey(event,root,'[data-settings-tab]',button);
 });
 root.querySelector('[data-manage-device-access]')?.addEventListener('click',()=>root.querySelector('[data-settings-tab=users]').click());
 root.querySelectorAll('[data-settings-device]').forEach(button=>button.onclick=()=>managementSelectDevice(button.dataset.settingsDevice));
 root.querySelector('#settings-device-select')?.addEventListener('change',event=>managementSelectDevice(event.target.value));
 root.querySelectorAll('[data-settings-device-tab]').forEach(button=>{
  button.onclick=()=>{managementSelectDevice(state.settingsDevice,button.dataset.settingsDeviceTab);root.querySelector('[data-settings-device-tab="'+state.settingsDeviceTab+'"]')?.focus();};
  button.onkeydown=event=>managementTabKey(event,root,'[data-settings-device-tab]',button);
 });
 root.querySelector('[data-connection-new]').onclick=()=>managementDialog('connection');root.querySelector('[data-user-new]').onclick=()=>managementDialog('user');
 root.querySelectorAll('[data-connection-edit]').forEach(button=>button.onclick=()=>managementDialog('connection',managementDevice(button.dataset.connectionEdit)));
 root.querySelectorAll('[data-key-new]').forEach(button=>button.onclick=()=>managementDialog('credential',null,button.dataset.keyNew));
 root.querySelectorAll('[data-key-edit]').forEach(button=>button.onclick=()=>{const key=data.credentials.find(key=>String(key.id)===button.dataset.keyEdit);managementDialog('credential',key,key.connection_id);});
 root.querySelectorAll('[data-key-toggle]').forEach(button=>button.onclick=()=>managementToggleCredential(data.credentials.find(key=>String(key.id)===button.dataset.keyToggle),button));
 root.querySelectorAll('[data-key-delete]').forEach(button=>button.onclick=()=>{const key=data.credentials.find(key=>String(key.id)===button.dataset.keyDelete),guard=managementLastKeyMessage(key);if(guard){managementKeyError(guard);return;}managementDialog('delete_credential',key,key.connection_id);});
 root.querySelector('[data-management-list-reload]')?.addEventListener('click',()=>{if(!managementSaving)load();});
 root.querySelectorAll('[data-user-edit],[data-user-reset]').forEach(button=>button.onclick=()=>managementDialog(button.dataset.userReset?'password':'user',data.users.find(user=>String(user.id)===(button.dataset.userEdit||button.dataset.userReset))));
 root.querySelectorAll('[data-device-live]').forEach(button=>button.onclick=()=>changeFortigate(button.dataset.deviceLive,'fortigate'));
 root.querySelectorAll('[data-key-test]').forEach(button=>button.onclick=async()=>{if(managementSaving)return;button.disabled=true;try{await managementPost('test_credential',{id:button.dataset.keyTest});toast('Bağlantı sınaması sıraya alındı.');await load();}catch(error){managementKeyError(error.message);button.disabled=false;}});
}
function managementTabKey(event,root,selector,button){
 if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();
 const buttons=[...root.querySelectorAll(selector)],index=buttons.indexOf(button),next=event.key==='Home'?0:event.key==='End'?buttons.length-1:(index+(event.key==='ArrowRight'?1:buttons.length-1))%buttons.length;buttons[next].click();
}
function managementDeviceCaption(){
 const d=managementConnections.find(c=>String(c.id)===state.fgDevice);
 const label=document.querySelector('.top-device');if(!label||!d)return;label.replaceChildren();const dot=document.createElement('span');dot.className='status-dot'+(Number(d.enabled)?'':' bad');label.append(dot,document.createTextNode(' '+d.name));label.title='Seçili FortiGate · '+d.serial+' · '+d.vdom;$('#api-device').value=state.fgDevice;
}
async function loadConnectionChoices(signal){
 const current=state.fgDevice,d=await api('connection_devices',false,{},signal);
 if(signal?.aborted||state.fgDevice!==current)return;
 managementConnections=d.devices;const fast=document.querySelector('#period option[value=fast]');if(fast)fast.textContent='Ayrıntılı analiz · son '+(d.fast_window_days||45)+' gün';const select=$('#api-device'),available=d.devices.some(c=>String(c.id)===current);
 if(current&&!available){controller?.abort();location.replace('/?view='+(!d.devices.length?'settings':'overview'));throw new DOMException('Erişim değişti','AbortError');}
 select.innerHTML=d.devices.length?d.devices.map(c=>`<option value="${c.id}">${esc(c.name)} · ${esc(c.vdom)}${Number(c.enabled)?'':' · devre dışı'}</option>`).join(''):'<option value="">FortiGate erişimi atanmamış</option>';
 if(!current&&d.devices.length)state.fgDevice=String(d.selected_id);
 select.value=state.fgDevice;select.disabled=!d.devices.length||fortigatePreferenceSaving;
 $('#device-access-banner').hidden=Boolean(d.devices.length);
 document.querySelectorAll('#navigation [data-view]').forEach(b=>{const host=['system','archive'].includes(b.dataset.view);b.hidden=host&&document.documentElement.dataset.userRole!=='admin';b.disabled=!d.devices.length&&!host&&b.dataset.view!=='settings';});
 managementDeviceCaption();select.onchange=()=>changeFortigate(select.value);
}
function bindSettings(){
 const dialog=document.createElement('dialog');dialog.id='management-dialog';dialog.className='management-dialog';dialog.setAttribute('aria-labelledby','management-dialog-title');dialog.innerHTML='<div class="management-dialog-heading"><h2 id="management-dialog-title"></h2><button type="button" class="icon-button" aria-label="Ayar penceresini kapat">×</button></div><form id="management-form"></form>';document.body.append(dialog);
 dialog.querySelector('.icon-button').onclick=()=>{if(!managementSaving)dialog.close();};dialog.addEventListener('cancel',e=>{if(managementSaving)e.preventDefault();});dialog.addEventListener('close',()=>{dialog.querySelectorAll('input[type=password]').forEach(e=>e.value='');managementFocus?.focus();});
 $('#management-form').onsubmit=async event=>{
  event.preventDefault();if(managementSaving)return;const form=event.currentTarget,values=Object.fromEntries(new FormData(form));
  if(form.dataset.kind==='credential'&&values.id&&values.enabled==='0'){
   const key=managementData.credentials.find(item=>String(item.id)===String(values.id)),guard=key&&managementLastKeyMessage(key);
   if(guard){$('#management-error').textContent=guard;form.querySelectorAll('input[type=password]').forEach(input=>input.value='');return;}
  }
  if(form.dataset.kind==='user'){values.device_ids=JSON.stringify(Array.from(form.querySelectorAll('[name=device_access]:checked'),e=>Number(e.value)));delete values.device_access;}const route={connection:'save_connection',credential:'save_credential',user:'save_user',password:'reset_user_password',delete_credential:'delete_credential'}[form.dataset.kind];managementSaving=true;dialog.querySelectorAll('button').forEach(b=>b.disabled=true);$('#management-error').textContent='';
  try{const saved=await managementPost(route,values);if(form.dataset.kind==='connection'&&!values.id){state.settingsDevice=String(saved.id);state.settingsDeviceTab='keys';state.setupDevice='';state.settingsTab='connections';syncUrl('push');}dialog.close();toast(form.dataset.kind==='delete_credential'?'API anahtarı silindi.':'Ayarlar kaydedildi.');await load();}
  catch(e){$('#management-error').textContent=e.message;$('#management-reload').hidden=e.status!==409;}
  finally{managementSaving=false;form.querySelectorAll('input[type=password]').forEach(e=>e.value='');dialog.querySelectorAll('button').forEach(b=>b.disabled=false);}
 };
 $('#device-preference-retry').onclick=()=>rememberFortigate(fortigatePreferenceFailed);
 // Choices are refreshed before every page load, including open sessions after a grant changes.
}

function changeFortigate(id,view=state.view){
 if(!managementConnections.some(d=>String(d.id)===String(id)))return;
 state.fgDevice=String(id);rememberFortigate(state.fgDevice);state.filters=eventFilterDefaults('all_blocks');state.page=1;state.vpnPage=1;state.vpnLogPage=1;state.vpnFilters={vpn_user:'',vpn_peer:'',vpn_type:''};
 state.allowedFilters=typeof allowedReadFilters==='function'?allowedReadFilters(new URLSearchParams()):{};state.allowedPage=1;state.allowedGroup='';state.allowedRecordsPage=1;
 state.portFilters=portReadFilters(new URLSearchParams());state.portPage=1;state.portGroup='';state.portRecordsPage=1;
 state.sourceIp='';state.targetKey='';state.targetOriginSource='';state.policyId='';state.profileName='';state.reasonRef='';state.historyPage=1;state.historyFilters={history_kind:'',history_q:'',history_object:'',history_baseline:'0'};state.impactChange='';state.alertPage=1;
 fgCurrentConfig=null;if(typeof fgPolicySearch!=='undefined')fgPolicySearch='';if(typeof fgPolicyPage!=='undefined')fgPolicyPage=1;optionsLoaded=false;detailId='';clearImpactAnchor();syncFilters();managementDeviceCaption();
 for(const id of ['event-dialog','profile-dialog','history-dialog','config-dialog','cold-event-dialog']){const dialog=document.getElementById(id);if(dialog?.open)dialog.close();}
 const next=['source','target','policy','profile','reason','impact'].includes(view)?'overview':view;toast('Seçili FortiGate: '+managementConnections.find(d=>String(d.id)===state.fgDevice).name);setView(next);
}

let fortigatePreferencePending='',fortigatePreferenceSaving=false,fortigatePreferenceFailed='';
function fortigatePreferenceStatus(text,error=false){
 $('#device-preference-status').textContent=text;$('#device-preference-retry').hidden=!error;
 $('#api-device').title=error?'Bu cihaz seçili; tercih hesaba kaydedilemedi. Ünlem düğmesinden yeniden deneyin.':'Son seçtiğiniz FortiGate hesabınızda hatırlanır.';
}
async function rememberFortigate(id){
 if(!id)return;fortigatePreferencePending=String(id);fortigatePreferenceFailed='';
 if(fortigatePreferenceSaving)return;fortigatePreferenceSaving=true;$('#api-device').disabled=true;
 try{
  while(fortigatePreferencePending){
   const sent=fortigatePreferencePending;fortigatePreferencePending='';fortigatePreferenceStatus('FortiGate tercihi hesabınıza kaydediliyor.');
   try{
    const response=await fetch('/api.php?route=save_fortigate_preference',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content},body:new URLSearchParams({connection_id:sent})});
    if(!response.ok)throw new Error('save');const data=await response.json();if(String(data.fg_device)!==sent||data.saved!==true)throw new Error('save');
    if(!fortigatePreferencePending)fortigatePreferenceStatus('FortiGate tercihi hesabınıza kaydedildi.');
   }catch(_){
    if(fortigatePreferencePending)continue;
    fortigatePreferenceFailed=sent;fortigatePreferenceStatus('Cihaz bu sayfada seçildi; hesaba kaydedilemedi. Yeniden deneyin.',true);toast('FortiGate tercihi hesaba kaydedilemedi. Seçicinin yanındaki ünlemden yeniden deneyin.');
   }
  }
 }finally{fortigatePreferenceSaving=false;$('#api-device').disabled=!managementConnections.length;}
}

function managementReadState(root,title,message,retry){
 root.innerHTML=`<section class="panel management-read-state" role="status"><h3>${esc(title)}</h3><p>${esc(message)}</p>${retry?'<button type="button" class="button" data-management-read-retry>Yeniden dene</button>':''}</section>`;
 if(retry)root.querySelector('[data-management-read-retry]').onclick=()=>retry();
}
async function managementLoadArchive(root){
 if(!root)return;root.setAttribute('aria-busy','true');managementReadState(root,'Arşiv ve yedekleme','Yedekleme ayarları yükleniyor…');
 try{await archiveRefresh(root,true);}
 catch(error){if(root.isConnected&&error.name!=='AbortError')managementReadState(root,'Arşiv ve yedekleme','Yedekleme ayarları alınamadı. Yeniden deneyebilirsiniz.',()=>managementLoadArchive(root));}
 finally{if(root.isConnected)root.setAttribute('aria-busy','false');}
}
async function loadRetentionSettings(root){
 if(!root||document.documentElement.dataset.userRole!=='admin')return;
 const request=(root.flsReadRequest||0)+1;root.flsReadRequest=request;root.setAttribute('aria-busy','true');managementReadState(root,'Veri saklama','Saklama ayarları yükleniyor…');
 try{const data=await api('retention_policy');if(!root.isConnected||root.flsReadRequest!==request)return;root.innerHTML=retentionPanel(data);bindRetentionPolicy();}
 catch(error){if(root.isConnected&&root.flsReadRequest===request&&error.name!=='AbortError')managementReadState(root,'Veri saklama','Saklama ayarları alınamadı. Lisans ve arşiv kopyalarını incelemeye devam edebilirsiniz.',()=>loadRetentionSettings(root));}
 finally{if(root.isConnected&&root.flsReadRequest===request)root.setAttribute('aria-busy','false');}
}
async function loadProductSettings(root){
 if(!root||document.documentElement.dataset.userRole!=='admin')return;
 root.innerHTML='<div id="product-license-content"></div><div id="product-retention-content"></div><div id="product-cold-content"></div>';
 await Promise.all([loadLicensePanel(root.querySelector('#product-license-content')),loadRetentionSettings(root.querySelector('#product-retention-content')),loadColdStoragePanel(root.querySelector('#product-cold-content'))]);
}
