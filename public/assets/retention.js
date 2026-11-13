'use strict';
let retentionModel=null,retentionDraft=null,retentionSaving=false,retentionError='';
let retentionPreview=null,retentionPreviewBusy=false,retentionExistingData='',retentionPreviewRequest=0;
const retentionChoices={fast_days:[45,70,90],retention_years:[2,3,4]};
function validRetentionSelection(values){return Object.entries(retentionChoices).every(([key,choices])=>choices.some(n=>String(n)===String(values?.[key])));}
function retentionHistoryScope(value){if(![0,1].includes(value.analysis_existing)||![0,1].includes(value.archive_existing))return 'Önceki sürüm';return [value.analysis_existing===1?'Analiz süresi':'',value.archive_existing===1?'Arşiv süresi':''].filter(Boolean).join(' ve ')||'Önceki koruma sürer';}
function retentionOptions(key,value){const choices=retentionChoices[key],suffix=key==='fast_days'?'gün':'takvim yılı',legacy=!choices.some(n=>String(n)===String(value));return (legacy?`<option value="${esc(value)}" selected disabled>${esc(value)} ${suffix} · önceki ayar</option>`:'')+choices.map(n=>`<option value="${n}" ${String(value)===String(n)?'selected':''}>${n} ${suffix}${n===(key==='fast_days'?45:2)?' · varsayılan':''}</option>`).join('');}
function acceptRetentionPolicy(data){if(data?.settings&&(!retentionModel||data.settings.revision>=retentionModel.settings.revision)){if(retentionModel&&data.settings.revision!==retentionModel.settings.revision)clearRetentionPreview();retentionModel=data;}const option=document.querySelector('#period option[value=fast]');if(option&&retentionModel?.settings)option.textContent='Ayrıntılı analiz · son '+retentionModel.settings.fast_days+' gün';}
function clearRetentionPreview(){retentionPreview=null;retentionExistingData='';retentionPreviewBusy=false;retentionPreviewRequest++;}
function retentionReduction(values=retentionDraft){const current=retentionModel?.settings;return Boolean(current&&values&&(Number(values.fast_days)<Number(current.fast_days)||Number(values.retention_years)<Number(current.retention_years)));}
function retentionPreviewMatches(preview=retentionPreview,values=retentionDraft){const current=retentionModel?.settings;return Boolean(preview&&values&&current&&preview.before?.revision===current.revision&&String(preview.before.fast_days)===String(current.fast_days)&&String(preview.before.retention_years)===String(current.retention_years)&&String(preview.after?.fast_days)===String(values.fast_days)&&String(preview.after?.retention_years)===String(values.retention_years)&&String(values.revision)===String(current.revision));}
function retentionPreviewFresh(){if(!retentionPreviewMatches()||typeof retentionPreview.preview_token!=='string'||!retentionPreview.preview_token)return false;const expiry=Date.parse(retentionPreview.expires_at);return Number.isFinite(expiry)&&expiry>Date.now();}
function retentionSaveState(){const current=retentionModel?.settings,conflict=Boolean(current&&retentionDraft&&retentionDraft.revision!==current.revision),reduction=retentionReduction(),review=retentionPreviewFresh(),busy=retentionSaving||retentionPreviewBusy;return {disabled:!retentionDraft||busy||conflict||!validRetentionSelection(retentionDraft)||(reduction&&review&&!['preserve','apply'].includes(retentionExistingData)),label:retentionSaving?'Kaydediliyor…':retentionPreviewBusy?'Önizleme hazırlanıyor…':reduction?(review?'Seçimle kaydet':retentionPreview?'Önizlemeyi yenile':'Etkiyi önizle'):'Ayarları kaydet'};}
function retentionReviewPanel(){
 if(!retentionPreviewMatches())return '';
 const p=retentionPreview,changes=[p.reduced?.analysis?`Ayrıntılı analiz: ${esc(p.before.fast_days)} → ${esc(p.after.fast_days)} gün`:'',p.reduced?.archive?`İmzalı log arşivi: ${esc(p.before.retention_years)} → ${esc(p.after.retention_years)} yıl`:''].filter(Boolean),fresh=retentionPreviewFresh();
 return `<section class="retention-review" id="retention-review" aria-labelledby="retention-review-heading"><h4 id="retention-review-heading" tabindex="-1">Süre azaltma önizlemesi</h4><p class="retention-review-changes">${changes.join('<br>')}</p>${retentionImpactPanel(p.impact||{},p.reduced||{})}<p class="retention-note">Seçim yalnız azaltılan süreyi etkiler. Diğer süre için mevcut koruma değişmez.</p><fieldset class="retention-scope"><legend>Mevcut kayıtlar</legend><label><input type="radio" name="existing_data" value="preserve" ${retentionExistingData==='preserve'?'checked':''} ${retentionSaving?'disabled':''}><span><strong>Mevcut kayıtların önceki süresini koru</strong><small>Yeni kısa süre yalnız bu değişiklikten sonra alınan kayıtlara uygulanır.</small></span></label><label><input type="radio" name="existing_data" value="apply" ${retentionExistingData==='apply'?'checked':''} ${retentionSaving?'disabled':''}><span><strong>Yeni süreyi mevcut kayıtlara da uygula</strong><small>Önceki kayıtların ilgili koruma süresi veya arşiv adaylığı yeni süreye göre hesaplanır. Arşiv için 2 yıllık alt sınır ve özel saklama kilitleri korunur.</small></span></label></fieldset><p class="retention-review-warning"><strong>Bu kayıt işlemi logları silmez ve disk alanı boşaltmaz.</strong> Fiziksel arşive taşıma ve silme henüz etkin değil. Harici kopyalar değişmez.</p><div class="retention-review-footer"><small>${fresh?'Önizleme: '+esc(trTime(p.checked_at,true))+' · Geçerlilik: '+esc(trTime(p.expires_at,true)):'Önizlemenin süresi doldu. Kaydetmeden önce yenileyin.'}</small><button type="button" class="text-button" id="retention-preview-cancel" ${retentionSaving?'disabled':''}>Önizlemeyi kapat</button></div></section>`;
}
function retentionImpactPanel(impact,reduced){
 const measured=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0?new Intl.NumberFormat('tr-TR').format(value):'Ölçülemedi';
 const cards=[['analysis','Ayrıntılı analiz'],['archive','İmzalı log arşivi']].filter(([key])=>reduced[key]===true).map(([key,label])=>{
  const value=impact[key]||{};return `<div class="retention-impact-card" data-retention-impact="${key}"><h5>${label}</h5><dl><div><dt>Saatlik kaynak</dt><dd>${esc(measured(value.files))}</dd></div><div><dt>Kayıt</dt><dd>${esc(measured(value.records))}</dd></div><div><dt>Ham kaynak boyutu</dt><dd>${esc(typeof value.raw_bytes==='number'&&Number.isFinite(value.raw_bytes)&&value.raw_bytes>=0?retentionBytes(value.raw_bytes):'Ölçülemedi')}</dd></div><div><dt>Yeni sınır · İstanbul</dt><dd>${esc(value.cutoff_utc?trTime(value.cutoff_utc,true):'Ölçülemedi')}</dd></div></dl></div>`;
 });
 return `<div class="retention-impact"><h5>Katalog adayları</h5><p>Yeni tarih sınırının dışındaki imzalı ve tamamen indekslenmiş saatlik kaynakların tamamı. Yalnız bu değişiklikle eklenen fark değildir.</p><div class="retention-impact-cards">${cards.join('')}</div><p class="retention-impact-measurement">Ölçülemeyen dosya: <strong>${esc(measured(impact.unknown_files))}</strong> · Ölçüm: ${esc(impact.measured_at?trTime(impact.measured_at,true):'Bilinmiyor')}</p><p>Bu sayım kesin silme listesi değildir; imza ve alım bütünlüğü ayrıca doğrulanmalıdır. Ham kaynak boyutu, boşalacak SQL veya disk alanı değildir.</p></div>`;
}
function retentionBytes(value){
 if(value===null||value===undefined)return 'Ölçüm yok';let amount=Number(value),i=0;const units=['B','KiB','MiB','GiB','TiB','PiB'];
 while(amount>=1024&&i<units.length-1){amount/=1024;i++;}return new Intl.NumberFormat('tr-TR',{maximumFractionDigits:i?1:0}).format(amount)+' '+units[i];
}
function retentionCapacityVolumes(capacity){
 const card=(label,volume,note='')=>`<div><span>${esc(label)}</span><strong>${esc(retentionBytes(volume?.available===false?null:volume?.free_bytes))}</strong><small>${esc(retentionBytes(volume?.available===false?null:volume?.total_bytes))} toplam${note?' · '+esc(note):''}</small></div>`;
 if(capacity.volumes_shared===true)return card('Sistem, log ve yedek boş alanı',capacity.system_volume,'Aynı dosya sistemi');
 if(capacity.system_volume||capacity.log_volume)return card('Sistem diski boş alanı',capacity.system_volume)+card('Log ve yedek diski boş alanı',capacity.log_volume);
 return card('Disk boş alan',capacity.volume);
}
function retentionPanel(data){
 acceptRetentionPolicy(data);const m=retentionModel,s=m?.settings,d=retentionDraft||s,conflict=Boolean(s&&retentionDraft&&retentionDraft.revision!==s.revision),c=m?.capacity,save=retentionSaveState();
 return `<section class="panel retention-panel" id="retention-policy-panel" aria-labelledby="retention-policy-heading"><div class="panel-heading"><div><h3 id="retention-policy-heading">Veri saklama</h3><p>Ayrıntılı analiz ve imzalı log arşivi.</p></div><span class="tag pass">Silme kapalı</span></div>${s?`<form id="retention-policy-form"><div class="retention-fields"><label>Ayrıntılı analiz süresi<select name="fast_days" required ${retentionSaving||retentionPreviewBusy?'disabled':''}>${retentionOptions('fast_days',d.fast_days)}</select><small>45, 70 veya 90 gün · varsayılan 45 gün</small></label><label>İmzalı log arşivi saklama süresi<select name="retention_years" required ${retentionSaving||retentionPreviewBusy?'disabled':''}>${retentionOptions('retention_years',d.retention_years)}</select><small>2, 3 veya 4 yıl · en az ve varsayılan 2 yıl</small></label></div><p class="retention-note">Süreler kaydedilir. Fiziksel arşive taşıma ve alan boşaltma henüz etkin değil. Ayrıntılı analiz süresi hızlı tarih önayarını belirler; eski SQL kayıtları mevcut sorgularda korunur. Bu ayar SSD’deki veritabanını otomatik küçültmez.</p><p class="retention-note">Arşiv saklama süresi sunucuya alım zamanından hesaplanır. Süre azaltılırken mevcut kayıtların kapsamı önizlemede seçilir. Bağımsız sağlayıcı zaman damgası ayrıca yapılandırılır; bu ayar damgalamayı etkinleştirmez.</p><p class="retention-note">Bu saklama politikası yerel log ve arşiv silmez. FTP, FTPS, SCP ve diğer uzak log/arşiv kopyalarının rotasyonu kullanıcıya aittir. Günlük logsuz DB dump yedeklerinin ayrı 7 günlük rotasyonu bu kapsamın dışındadır.</p><p class="retention-note" id="retention-policy-legacy" ${validRetentionSelection(d)?'hidden':''}>Önceki ayar yeni seçeneklerin dışında. Kaydetmek için desteklenen süreleri seçin.</p>${retentionReviewPanel()}<div class="retention-actions"><button type="submit" class="button primary" id="retention-policy-save" ${save.disabled?'disabled':''}>${save.label}</button><span class="muted" id="retention-policy-draft">${retentionDraft?'Kaydedilmemiş değişiklikler':''}</span><button type="button" class="text-button" id="retention-policy-reload" ${conflict?'':'hidden'}>Güncel ayarları yükle</button></div><p class="retention-error" role="alert" id="retention-policy-error" ${retentionError||conflict?'':'hidden'}>${esc(retentionError||(conflict?'Ayarlar başka bir oturumda değişti. Güncel ayarları yükleyin.':''))}</p></form><p class="retention-meta">Son kayıt: ${esc(trTime(s.updated_at,true))} · ${esc(s.updated_by==='system'?'İlk ayar':s.updated_by)} · Sürüm ${esc(s.revision)}</p>${c?`<div class="retention-capacity"><div><span>Ham log</span><strong>${esc(retentionBytes(c.raw.bytes))}</strong><small>${esc(new Intl.NumberFormat('tr-TR').format(c.raw.files))} saatlik dosya</small></div><div><span>Veritabanı ve indeks</span><strong>${esc(retentionBytes(c.database.data_bytes+c.database.index_bytes))}</strong><small>InnoDB tahmini</small></div><div><span>İmzalı paketler</span><strong>${esc(retentionBytes(c.packages.bytes))}</strong><small>${esc(c.packages.ready)} hazır paket</small></div>${retentionCapacityVolumes(c)}</div><p class="retention-note">Günlük ham veri: ${esc(retentionBytes(c.daily_raw_bytes))} · ${esc(s.retention_years)} yıllık sıkıştırılmamış ham veri tahmini: ${esc(retentionBytes(c.retention_raw_projection_bytes))}. Veritabanı, indeks, imzalı paketler ve disk yedekliliği bu tahmine dahil değildir.</p>`:''}<details class="retention-history"><summary>Politika geçmişi · ${esc(m.history?.length||1)} sürüm</summary><div class="table-wrap"><table><thead><tr><th>Sürüm</th><th>Etkin başlangıç</th><th>Arşiv saklama</th><th>Ayrıntılı analiz</th><th>Mevcut kayıtlara uygulama</th><th>Kaydeden</th></tr></thead><tbody>${(m.history||[]).map(v=>`<tr><td>${esc(v.revision)}</td><td>${v.revision===1?'Mevcut kayıtlar dahil':esc(trTime(v.effective_at,true))}</td><td>${esc(v.retention_years)} yıl</td><td>${esc(v.fast_days)} gün</td><td>${retentionHistoryScope(v)}</td><td>${esc(v.recorded_by==='system'?'İlk ayar':v.recorded_by)}</td></tr>`).join('')}</tbody></table></div></details>`:`<p class="retention-note" role="status">Saklama ayarları okunamadı.</p><button class="button" id="retention-policy-reload">Yeniden yükle</button>`}</section>`;
}
function refreshRetentionPanel(){const panel=$('#retention-policy-panel');if(!panel)return;panel.outerHTML=retentionPanel(retentionModel);bindRetentionPolicy();}
function bindRetentionPolicy(){
 const form=$('#retention-policy-form'),reload=$('#retention-policy-reload');
 if(reload)reload.onclick=async()=>{try{const d=await api('retention_policy');acceptRetentionPolicy(d);retentionDraft=null;retentionError='';clearRetentionPreview();refreshRetentionPanel();}catch(e){toast(e.message);}};
 if(!form)return;
 if(document.documentElement.dataset.userRole!=='admin'){form.querySelectorAll('input,select,button').forEach(e=>e.disabled=true);return;}
 const cancel=$('#retention-preview-cancel');if(cancel)cancel.onclick=()=>{clearRetentionPreview();retentionError='';refreshRetentionPanel();$('#retention-policy-save')?.focus({preventScroll:true});};
 form.oninput=form.onchange=event=>{
  if(event.target?.name==='existing_data'){
   retentionExistingData=['preserve','apply'].includes(event.target.value)?event.target.value:'';
  }else{
   const s=retentionModel.settings,years=form.elements.retention_years.value,days=form.elements.fast_days.value;
   const changed=!retentionDraft||years!==retentionDraft.retention_years||days!==retentionDraft.fast_days;
   retentionDraft=years===String(s.retention_years)&&days===String(s.fast_days)?null:{retention_years:years,fast_days:days,revision:retentionDraft?.revision??s.revision};
   if(changed){clearRetentionPreview();$('#retention-review')?.remove();retentionError='';$('#retention-policy-error').hidden=true;}
  }
  $('#retention-policy-draft').textContent=retentionDraft?'Kaydedilmemiş değişiklikler':'';
  $('#retention-policy-legacy').hidden=validRetentionSelection(retentionDraft||retentionModel.settings);
  const save=retentionSaveState();$('#retention-policy-save').disabled=save.disabled;$('#retention-policy-save').textContent=save.label;
 };
 form.onsubmit=async event=>{
  event.preventDefault();
  const current=retentionModel.settings;
  if(!retentionDraft||retentionSaving||retentionPreviewBusy||!validRetentionSelection(retentionDraft)||retentionDraft.revision!==current.revision||!form.reportValidity())return;
  if(retentionReduction()&&!retentionPreviewFresh()){
   const values={...retentionDraft},request=++retentionPreviewRequest;retentionPreviewBusy=true;retentionError='';refreshRetentionPanel();
   try{
    const result=await api('preview_retention_policy',false,values);
    if(request!==retentionPreviewRequest)return;
    if(!retentionPreviewMatches(result,values)||result.reduced?.analysis!==(Number(values.fast_days)<Number(current.fast_days))||result.reduced?.archive!==(Number(values.retention_years)<Number(current.retention_years))||result.physical_cleanup_enabled!==false||typeof result.preview_token!=='string'||!result.preview_token||!Number.isFinite(Date.parse(result.expires_at))||Date.parse(result.expires_at)<=Date.now())throw new Error('Önizleme doğrulanamadı. Yeniden deneyin.');
    retentionPreview=result;retentionExistingData='';
   }catch(e){if(request!==retentionPreviewRequest)return;if(e.status===409){clearRetentionPreview();try{const latest=await api('retention_policy');acceptRetentionPolicy(latest);}catch{}retentionError=e.message;refreshRetentionPanel();}else retentionError=e instanceof TypeError?'Sunucuya ulaşılamadı. Değerler korunuyor.':e.message;}
   finally{if(request===retentionPreviewRequest){retentionPreviewBusy=false;refreshRetentionPanel();($('#retention-review-heading')||$('#retention-policy-save'))?.focus({preventScroll:true});}}
   return;
  }
  const values={...retentionDraft};
  if(retentionReduction()){
   if(!['preserve','apply'].includes(retentionExistingData))return;
   values.existing_data=retentionExistingData;values.preview_token=retentionPreview.preview_token;
  }
  retentionSaving=true;retentionError='';refreshRetentionPanel();
  try{
   const response=await fetch('/api.php?route=save_retention_policy',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body:new URLSearchParams(values)});
   if(response.status===401){location.href='/';return;}const result=await response.json();
   if(!response.ok){if(response.status===409){clearRetentionPreview();const latest=await api('retention_policy');acceptRetentionPolicy(latest);}throw new Error(result.error||'Saklama ayarları kaydedilemedi.');}
   retentionDraft=null;clearRetentionPreview();acceptRetentionPolicy({...retentionModel,settings:result.settings});const latest=await api('retention_policy');acceptRetentionPolicy(latest);toast(result.changed?'Saklama ayarları kaydedildi.':'Ayarlar zaten aynı.');
  }catch(e){retentionError=e instanceof TypeError?'Sunucuya ulaşılamadı. Değerler korunuyor.':e.message;}
  finally{retentionSaving=false;refreshRetentionPanel();$('#retention-policy-save')?.focus({preventScroll:true});}
 };
}
