'use strict';
let mailSearchBacklogSettingsModel=null,mailSearchBacklogSettingsDraft=null,mailSearchBacklogSettingsSaving=false,mailSearchBacklogSettingsError='';

function acceptMailSearchBacklogSettings(data){
 if(data?.settings&&(!mailSearchBacklogSettingsModel||data.settings.revision>=mailSearchBacklogSettingsModel.settings.revision))mailSearchBacklogSettingsModel=data;
}
function mailSearchBacklogSettingsPanel(data){
 if(!data&&mailSearchBacklogSettingsModel)mailSearchBacklogSettingsModel={...mailSearchBacklogSettingsModel,application:{status:'unknown'}};
 acceptMailSearchBacklogSettings(data);const m=mailSearchBacklogSettingsModel,s=m?.settings,d=mailSearchBacklogSettingsDraft||s,conflict=Boolean(s&&mailSearchBacklogSettingsDraft&&mailSearchBacklogSettingsDraft.revision!==s.revision),a=m?.application||{};
 const statuses={applied:['Etkin','pass'],pending:['Sonraki ölçüm bekleniyor','medium'],unknown:['Uygulama durumu doğrulanamadı','medium']},[label,color]=statuses[a.status]||statuses.unknown;
 return `<section class="panel backlog-settings-panel" id="mail-backlog-settings-panel" aria-labelledby="mail-backlog-settings-heading"><div class="panel-heading"><div><h3 id="mail-backlog-settings-heading">E-posta ve dosya arama indeksi · uyarı ayarları</h3><p>Sunucu genelinde · tüm cihazların arama indeksi. Özet indeksinden bağımsız eşik ve süre.</p></div>${s?`<span class="tag ${color}" id="mail-backlog-settings-application" role="status">Kaydedilen ayar: ${label}</span>`:''}</div>${s?`<form id="mail-backlog-settings-form"><div class="backlog-settings-fields"><label for="mail-backlog-minimum-pending">Bekleyen kayıt eşiği<input id="mail-backlog-minimum-pending" name="minimum_pending" type="number" min="1" max="100000000" step="1" required inputmode="numeric" value="${esc(d.minimum_pending)}" ${mailSearchBacklogSettingsSaving?'disabled':''}><small>1–100.000.000 kayıt</small></label><label for="mail-backlog-minimum-minutes">Bekleme süresi (dakika)<input id="mail-backlog-minimum-minutes" name="minimum_minutes" type="number" min="1" max="1440" step="1" required inputmode="numeric" value="${esc(d.minimum_minutes)}" ${mailSearchBacklogSettingsSaving?'disabled':''}><small>1–1.440 dakika</small></label></div><p class="backlog-settings-help">Eşik ve üzerinde kesintisiz bekleme uyarı oluşturur. Değişen kural sonraki 30 saniyelik ölçümde uygulanır; süre yeniden başlar. Aynı değerler süreyi sıfırlamaz. Açılan uyarı geçerli sıfır ölçümüyle kapanır.</p><div class="backlog-settings-actions"><button type="submit" class="button primary" id="mail-backlog-settings-save" ${!mailSearchBacklogSettingsDraft||mailSearchBacklogSettingsSaving||conflict?'disabled':''}>${mailSearchBacklogSettingsSaving?'Kaydediliyor…':'Ayarları kaydet'}</button><span id="mail-backlog-settings-draft" class="muted">${mailSearchBacklogSettingsDraft?'Kaydedilmemiş değişiklikler':''}</span><button type="button" class="text-button" id="mail-backlog-settings-reload" ${conflict?'':'hidden'}>Güncel ayarları yükle</button></div><p class="backlog-settings-error" id="mail-backlog-settings-error" role="alert" ${mailSearchBacklogSettingsError||conflict?'':'hidden'}>${esc(mailSearchBacklogSettingsError||(conflict?'Ayarlar başka bir oturumda değişti. Güncel ayarları yükleyin.':''))}</p></form><p class="backlog-settings-meta">Son kayıt: ${esc(trTime(s.updated_at,true))} · ${esc(s.updated_by==='system'?'İlk ayar':s.updated_by)} · Bu ayarlar tarih filtresinden bağımsızdır.</p>`:`<p class="backlog-settings-help" role="status">Ayarlar şu anda okunamıyor. Yenileyip tekrar deneyin.</p><button type="button" class="button" id="mail-backlog-settings-reload">Ayarları yükle</button>`}</section>`;
}
function refreshMailSearchBacklogSettingsPanel(){
 const panel=$('#mail-backlog-settings-panel');if(!panel||state.view!=='system')return;
 panel.outerHTML=mailSearchBacklogSettingsPanel(mailSearchBacklogSettingsModel);bindMailSearchBacklogSettings();
}
function bindMailSearchBacklogSettings(){
 const form=$('#mail-backlog-settings-form'),reload=$('#mail-backlog-settings-reload');
 if(reload)reload.onclick=async()=>{
  try{const data=await api('mail_search_backlog_settings');acceptMailSearchBacklogSettings(data);mailSearchBacklogSettingsDraft=null;mailSearchBacklogSettingsError='';refreshMailSearchBacklogSettingsPanel();}catch(e){toast(e.message);}
 };
 if(!form)return;
 if(document.documentElement.dataset.userRole!=='admin'){form.querySelectorAll('input,button').forEach(e=>e.disabled=true);const note=document.createElement('p');note.className='management-help';note.textContent='Bu ayarları yalnız yöneticiler değiştirebilir.';form.append(note);return;}
 form.oninput=()=>{
  const s=mailSearchBacklogSettingsModel.settings,pending=form.elements.minimum_pending.value,minutes=form.elements.minimum_minutes.value;
  mailSearchBacklogSettingsDraft=pending===String(s.minimum_pending)&&minutes===String(s.minimum_minutes)?null:{minimum_pending:pending,minimum_minutes:minutes,revision:mailSearchBacklogSettingsDraft?.revision??s.revision};
  $('#mail-backlog-settings-draft').textContent=mailSearchBacklogSettingsDraft?'Kaydedilmemiş değişiklikler':'';
  $('#mail-backlog-settings-save').disabled=!mailSearchBacklogSettingsDraft||mailSearchBacklogSettingsSaving||Boolean(mailSearchBacklogSettingsDraft&&mailSearchBacklogSettingsDraft.revision!==s.revision);
 };
 form.onsubmit=async event=>{
  event.preventDefault();if(!mailSearchBacklogSettingsDraft||mailSearchBacklogSettingsSaving||!form.reportValidity())return;
  const values={...mailSearchBacklogSettingsDraft},body=new FormData();for(const[key,value]of Object.entries(values))body.set(key,String(value));
  mailSearchBacklogSettingsSaving=true;mailSearchBacklogSettingsError='';refreshMailSearchBacklogSettingsPanel();
  try{
   const response=await fetch('/api.php?route=save_mail_search_backlog_settings',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
   if(response.status===401){location.href='/';return;}
   const data=await response.json();if(data.settings)acceptMailSearchBacklogSettings(data);
   if(!response.ok)throw new Error(data.error||'Ayarlar kaydedilemedi.');
   mailSearchBacklogSettingsDraft=null;toast(data.changed?'Kaydedildi. Yeni değerler sonraki ölçümde uygulanacak.':'Ayarlar zaten aynı.');
  }catch(e){mailSearchBacklogSettingsError=e instanceof TypeError?'Sunucuya ulaşılamadı. Girilen değerler korunuyor; yeniden deneyin.':e.message;}
  finally{mailSearchBacklogSettingsSaving=false;refreshMailSearchBacklogSettingsPanel();$('#mail-backlog-settings-save')?.focus({preventScroll:true});}
 };
}
