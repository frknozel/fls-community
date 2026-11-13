'use strict';
let backlogSettingsModel=null,backlogSettingsDraft=null,backlogSettingsSaving=false,backlogSettingsError='';

function acceptBacklogSettings(data){
 if(data?.settings&&(!backlogSettingsModel||data.settings.revision>=backlogSettingsModel.settings.revision))backlogSettingsModel=data;
}
function backlogSettingsPanel(data){
 if(!data&&backlogSettingsModel)backlogSettingsModel={...backlogSettingsModel,application:{status:'unknown'}};
 acceptBacklogSettings(data);const m=backlogSettingsModel,s=m?.settings,d=backlogSettingsDraft||s,conflict=Boolean(s&&backlogSettingsDraft&&backlogSettingsDraft.revision!==s.revision),a=m?.application||{};
 const statuses={applied:['Etkin','pass'],pending:['Sonraki ölçüm bekleniyor','medium'],unknown:['Uygulama durumu doğrulanamadı','medium']},[label,color]=statuses[a.status]||statuses.unknown;
 return `<section class="panel backlog-settings-panel" id="backlog-settings-panel" aria-labelledby="backlog-settings-heading"><div class="panel-heading"><div><h3 id="backlog-settings-heading">Özet indeksi · uyarı ayarları</h3><p>Sunucu genelinde · tüm cihazların özet indeksini izler.</p></div>${s?`<span class="tag ${color}" id="backlog-settings-application" role="status">Kaydedilen ayar: ${label}</span>`:''}</div>${s?`<form id="backlog-settings-form"><div class="backlog-settings-fields"><label for="backlog-minimum-pending">Bekleyen kayıt eşiği<input id="backlog-minimum-pending" name="minimum_pending" type="number" min="1" max="100000000" step="1" required inputmode="numeric" value="${esc(d.minimum_pending)}" ${backlogSettingsSaving?'disabled':''}><small>1–100.000.000 kayıt</small></label><label for="backlog-minimum-minutes">Bekleme süresi (dakika)<input id="backlog-minimum-minutes" name="minimum_minutes" type="number" min="1" max="1440" step="1" required inputmode="numeric" value="${esc(d.minimum_minutes)}" ${backlogSettingsSaving?'disabled':''}><small>1–1.440 dakika</small></label></div><p class="backlog-settings-help">Bekleyen sayı bu değerde veya üzerinde belirtilen süre boyunca kalırsa uyarı görünür. Yeni değerler sonraki 30 saniyelik ölçümde uygulanır; süre yeni kurala göre yeniden başlar. Aynı değerleri kaydetmek süreyi sıfırlamaz. Uyarı, sıfır bekleyen kayıt doğrulandığında kalkar.</p><div class="backlog-settings-actions"><button type="submit" class="button primary" id="backlog-settings-save" ${!backlogSettingsDraft||backlogSettingsSaving||conflict?'disabled':''}>${backlogSettingsSaving?'Kaydediliyor…':'Ayarları kaydet'}</button><span id="backlog-settings-draft" class="muted">${backlogSettingsDraft?'Kaydedilmemiş değişiklikler':''}</span><button type="button" class="text-button" id="backlog-settings-reload" ${conflict?'':'hidden'}>Güncel ayarları yükle</button></div><p class="backlog-settings-error" id="backlog-settings-error" role="alert" ${backlogSettingsError||conflict?'':'hidden'}>${esc(backlogSettingsError||(conflict?'Ayarlar başka bir oturumda değişti. Güncel ayarları yükleyin.':''))}</p></form><p class="backlog-settings-meta">Son kayıt: ${esc(trTime(s.updated_at,true))} · ${esc(s.updated_by==='system'?'İlk ayar':s.updated_by)} · Bu ayarlar tarih filtresinden bağımsızdır.</p>`:`<p class="backlog-settings-help" role="status">Ayarlar şu anda okunamıyor. Yenileyip tekrar deneyin.</p><button type="button" class="button" id="backlog-settings-reload">Ayarları yükle</button>`}</section>`;
}
function refreshBacklogSettingsPanel(){
 const panel=$('#backlog-settings-panel');if(!panel||state.view!=='system')return;
 panel.outerHTML=backlogSettingsPanel(backlogSettingsModel);bindBacklogSettings();
}
function bindBacklogSettings(){
 const form=$('#backlog-settings-form'),reload=$('#backlog-settings-reload');
 if(reload)reload.onclick=async()=>{
  try{const data=await api('backlog_settings');acceptBacklogSettings(data);backlogSettingsDraft=null;backlogSettingsError='';refreshBacklogSettingsPanel();}catch(e){toast(e.message);}
 };
 if(!form)return;
 if(document.documentElement.dataset.userRole!=='admin'){form.querySelectorAll('input,button').forEach(e=>e.disabled=true);const note=document.createElement('p');note.className='management-help';note.textContent='Bu ayarları yalnız yöneticiler değiştirebilir.';form.append(note);return;}
 form.oninput=()=>{
  const s=backlogSettingsModel.settings,pending=form.elements.minimum_pending.value,minutes=form.elements.minimum_minutes.value;
  backlogSettingsDraft=pending===String(s.minimum_pending)&&minutes===String(s.minimum_minutes)?null:{minimum_pending:pending,minimum_minutes:minutes,revision:backlogSettingsDraft?.revision??s.revision};
  $('#backlog-settings-draft').textContent=backlogSettingsDraft?'Kaydedilmemiş değişiklikler':'';
  $('#backlog-settings-save').disabled=!backlogSettingsDraft||backlogSettingsSaving||Boolean(backlogSettingsDraft&&backlogSettingsDraft.revision!==s.revision);
 };
 form.onsubmit=async event=>{
  event.preventDefault();if(!backlogSettingsDraft||backlogSettingsSaving||!form.reportValidity())return;
  const values={...backlogSettingsDraft},body=new FormData();for(const[key,value]of Object.entries(values))body.set(key,String(value));
  backlogSettingsSaving=true;backlogSettingsError='';refreshBacklogSettingsPanel();
  try{
   const response=await fetch('/api.php?route=save_backlog_settings',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
   if(response.status===401){location.href='/';return;}
   const data=await response.json();if(data.settings)acceptBacklogSettings(data);
   if(!response.ok)throw new Error(data.error||'Ayarlar kaydedilemedi.');
   backlogSettingsDraft=null;toast(data.changed?'Kaydedildi. Yeni değerler sonraki ölçümde uygulanacak.':'Ayarlar zaten aynı.');
  }catch(e){backlogSettingsError=e instanceof TypeError?'Sunucuya ulaşılamadı. Girilen değerler korunuyor; yeniden deneyin.':e.message;}
  finally{backlogSettingsSaving=false;refreshBacklogSettingsPanel();$('#backlog-settings-save')?.focus({preventScroll:true});}
 };
}
