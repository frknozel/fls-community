'use strict';
let archiveTlsSettingsModel=null,archiveTlsSettingsDraft=null,archiveTlsSettingsSaving=false,archiveTlsSettingsError='',archiveTlsSettingsNotice='';
let archiveTlsHistoryOpen=false,archiveTlsHistoryData=null,archiveTlsHistoryError='',archiveTlsHistoryLoading=false,archiveTlsHistorySequence=0;
const archiveTlsHistoryFilters={target:'0',status:'all',severity:'all',from:'',to:'',page:1};
const archiveTlsHistorySelected=new Set();
let archiveTlsHistoryDateDraft=null,archiveTlsHistoryExporting=false,archiveTlsHistoryExportError='',archiveTlsHistoryExportNotice='';
function archiveTlsHistoryValidDate(v){return v===''||/^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}$/.test(v)&&!Number.isNaN(Date.parse(v+'T00:00:00Z'))&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v;}
function archiveTlsHistoryQuery(){return Object.fromEntries(['target','status','severity','from','to','page'].map(k=>['tls_history_'+k,String(archiveTlsHistoryFilters[k])]));}
function archiveTlsHistoryResetSelection(){archiveTlsHistorySelected.clear();archiveTlsHistoryExportError='';archiveTlsHistoryExportNotice='';}
function archiveTlsHistorySelectionChange(ids,checked){
 const active=document.activeElement,focus=active?.id==='ftps-history-select-page'?'#ftps-history-select-page':active?.dataset.ftpsHistorySelect?'[data-ftps-history-select=\"'+active.dataset.ftpsHistorySelect+'\"]':null;
 if(checked&&new Set([...archiveTlsHistorySelected,...ids]).size>1000){archiveTlsHistoryExportError='Tek seferde en fazla 1.000 kayıt işaretlenebilir.';archiveTlsHistoryRender();return;}
 for(const id of ids)checked?archiveTlsHistorySelected.add(id):archiveTlsHistorySelected.delete(id);
 archiveTlsHistoryExportError='';archiveTlsHistoryExportNotice='';archiveTlsHistoryRender();if(focus)document.querySelector(focus)?.focus({preventScroll:true});
}
async function archiveTlsHistoryExport(selection){
 if(archiveTlsHistoryExporting||archiveTlsHistoryLoading||archiveTlsHistoryDateDraft||(typeof archiveTlsViewsBusy!=='undefined'&&archiveTlsViewsBusy))return;
 const body=new FormData();for(const[k,v]of Object.entries(archiveTlsHistoryQuery()))body.set(k,v);
 body.set('selection',selection);body.set('ids',selection==='selected'?[...archiveTlsHistorySelected].join(','):'');
 archiveTlsHistoryExporting=true;archiveTlsHistoryExportError='';archiveTlsHistoryExportNotice='';archiveTlsHistoryRender();
 try{
  const response=await fetch('/api.php?route=archive_tls_history_csv',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
  if(response.status===401){location.href='/';return;}
  if(!response.ok){const d=await response.json();throw new Error(d.error||'CSV oluşturulamadı.');}
  if(!(response.headers.get('content-type')||'').startsWith('text/csv'))throw new Error('CSV yanıtı alınamadı.');
  const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=(response.headers.get('content-disposition')||'').match(/filename="([a-zA-Z0-9_.-]+)"/)?.[1]||'fls-ftps-alert-history.csv';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
  const count=Number(response.headers.get('X-FLS-Export-Rows'));archiveTlsHistoryExportNotice=Number.isSafeInteger(count)?num(count)+' kayıt CSV olarak indirildi.':'CSV dosyası indirildi.';
 }catch(e){archiveTlsHistoryExportError=e instanceof TypeError?'Sunucuya ulaşılamadı. Seçiminiz korunuyor; yeniden deneyin.':e.message;}
 finally{archiveTlsHistoryExporting=false;archiveTlsHistoryRender();}
}

function archiveTlsHistoryRestore(p){
 const raw=p.get('tls_history_target')||'0',target=/^(0|[1-9][0-9]{0,9})$/.test(raw)&&Number(raw)<=4294967295?raw:'0';
 const status=['all','active','closed'].includes(p.get('tls_history_status'))?p.get('tls_history_status'):'all';
 const severity=['all','warning','error'].includes(p.get('tls_history_severity'))?p.get('tls_history_severity'):'all';
 let from=p.get('tls_history_from')||'',to=p.get('tls_history_to')||'';if(!archiveTlsHistoryValidDate(from)||!archiveTlsHistoryValidDate(to)||from&&to&&from>to){from='';to='';}
 const rawPage=p.get('tls_history_page')||'1',page=/^[1-9][0-9]{0,5}$/.test(rawPage)&&Number(rawPage)<=100000?Number(rawPage):1;
 if(target!==archiveTlsHistoryFilters.target||status!==archiveTlsHistoryFilters.status||page!==archiveTlsHistoryFilters.page||severity!==archiveTlsHistoryFilters.severity||from!==archiveTlsHistoryFilters.from||to!==archiveTlsHistoryFilters.to)archiveTlsHistoryData=null;
 archiveTlsHistoryOpen=p.get('tls_history_open')==='1'||p.get('system_focus')==='ftps-alert-history';
 Object.assign(archiveTlsHistoryFilters,{target,status,severity,from,to,page});archiveTlsHistoryDateDraft=null;archiveTlsHistoryResetSelection();++archiveTlsHistorySequence;archiveTlsHistoryLoading=false;archiveTlsHistoryError='';
}
function archiveTlsHistoryAppend(p){
 if(archiveTlsHistoryOpen)p.set('tls_history_open','1');
 if(archiveTlsHistoryFilters.target!=='0')p.set('tls_history_target',archiveTlsHistoryFilters.target);
 if(archiveTlsHistoryFilters.status!=='all')p.set('tls_history_status',archiveTlsHistoryFilters.status);
 for(const k of ['severity','from','to'])if(archiveTlsHistoryFilters[k]!==({severity:'all',from:'',to:''})[k])p.set('tls_history_'+k,archiveTlsHistoryFilters[k]);
 if(archiveTlsHistoryFilters.page>1)p.set('tls_history_page',String(archiveTlsHistoryFilters.page));
}
function archiveTlsHistorySyncUrl(){
 if(typeof syncUrl==='function'&&state.view==='system'){syncUrl();if(typeof lastArchiveHistoryFocus!=='undefined')lastArchiveHistoryFocus=location.search;}
}
function archiveTlsElapsed(seconds){
 if(seconds===null||seconds===undefined||!Number.isFinite(Number(seconds)))return 'Süre bilinmiyor';
 let minutes=Math.floor(Math.max(0,Number(seconds))/60);if(!minutes)return '1 dakikadan az';
 const days=Math.floor(minutes/1440);minutes%=1440;const hours=Math.floor(minutes/60);minutes%=60;
 return [days?num(days)+' gün':'',hours?num(hours)+' saat':'',minutes?num(minutes)+' dk':''].filter(Boolean).join(' ');
}
function archiveTlsAlertLink(alert){
 if(!Number.isInteger(alert.destination_id)||alert.destination_id<1||alert.destination_id>4294967295)return '/?view=system&system_tab=live&system_focus=ftps-certificates';
 return '/?'+new URLSearchParams({view:'system',system_tab:'live',system_focus:'ftps-alert-history',tls_history_open:'1',tls_history_target:String(alert.destination_id)});
}

function archiveTlsHistoryPanel(){
 return `<details id="ftps-alert-history" class="ftps-alert-history" tabindex="-1" ${archiveTlsHistoryOpen?'open':''}><summary><strong>Uyarı geçmişi</strong><span>Hedef, tetikleyen eşikler ve açılış / kapanış</span></summary><div id="ftps-history-content">${archiveTlsHistoryContent()}</div></details>`;
}
function archiveTlsHistoryContent(){
 const d=archiveTlsHistoryData;
 if(!d)return `<p class="ftps-certificate-help" role="status">${archiveTlsHistoryError?esc(archiveTlsHistoryError):'Geçmiş yükleniyor…'}</p>${archiveTlsHistoryError?'<button type="button" class="button" data-ftps-history-retry>Yeniden dene</button>':''}`;
 const types={certificate_expiring:'Sertifika süresi azalıyor',certificate_expired:'Sertifika süresi doldu',certificate_check_failed:'Doğrulama / bağlantı hatası',certificate_check_stale:'Sertifika kontrolü gecikti',certificate_unknown:'Sertifika henüz doğrulanmadı'};
 const reasons={recovered:'Koşul ortadan kalktı',settings_changed:'Eşikler değişti',severity_changed:'Uyarı seviyesi değişti',certificate_changed:'Sertifika değişti',destination_changed:'Hedef ayarı değişti',destination_inactive:'Hedef kapalı veya FTPS dışında',unconfirmed:'Koşul artık doğrulanamıyor',condition_changed:'Uyarı türü değişti'};
 const busy=archiveTlsHistoryLoading||archiveTlsHistoryExporting||(typeof archiveTlsViewsBusy!=='undefined'&&archiveTlsViewsBusy),dates=archiveTlsHistoryDateDraft||archiveTlsHistoryFilters,disabled=busy?'disabled':'';
 const rows=d.rows.map(r=>`<tr><td class="ftps-history-check"><input type="checkbox" data-ftps-history-select="${r.id}" aria-label="${esc('Kayıt '+r.id+' · '+r.destination_name)}" ${archiveTlsHistorySelected.has(String(r.id))?'checked':''} ${disabled}></td><td><strong>${esc(r.destination_name)}</strong><small class="mono">${esc(r.host)}:${esc(r.port)}</small><small>${esc(types[r.alert_code]||r.alert_code)}</small></td><td><span class="tag ${r.severity==='error'?'failed':'medium'}">${r.severity==='error'?'Kritik':'Uyarı'}</span></td><td>${esc(trTime(r.triggered_at,true))}<small data-ftps-history-duration>${esc(archiveTlsElapsed(r.duration_seconds))}${r.closed_at?' sürdü':' süredir açık'}</small></td><td>Uyarı: <strong>${num(r.warning_days)} gün</strong><small>Kritik: ${num(r.critical_days)} gün</small><small>${r.days_remaining_at_start===null?'Kalan süre doğrulanamadı':r.days_remaining_at_start<=0?'Başlangıçta süre dolmuştu':'Başlangıçta '+num(r.days_remaining_at_start)+' gün kalmıştı'}</small></td><td>${r.closed_at?`${esc(trTime(r.closed_at,true))}<small>${esc(reasons[r.closure_reason]||r.closure_reason)}</small>`:`<span class="tag medium">Açık</span><small>Son gözlem: ${esc(trTime(r.last_seen_at,true))}</small>`}</td></tr>`);
 return `${typeof archiveTlsViewsPanel==='function'?`<section id="ftps-saved-views" class="ftps-saved-views" aria-label="Kayıtlı FTPS incelemeleri">${archiveTlsViewsPanel()}</section>`:''}<div class="ftps-history-toolbar"><label>Yedekleme hedefi<select id="ftps-history-target" ${disabled}><option value="0">Tüm FTPS hedefleri</option>${d.targets.map(t=>`<option value="${t.id}" ${String(t.id)===archiveTlsHistoryFilters.target?'selected':''}>${esc(t.name)} · ${esc(t.host)}</option>`).join('')}</select></label><label>Durum<select id="ftps-history-status" ${disabled}>${[['all','Tümü'],['active','Açık'],['closed','Kapalı']].map(([v,t])=>`<option value="${v}" ${v===archiveTlsHistoryFilters.status?'selected':''}>${t}</option>`).join('')}</select></label><label>Uyarı seviyesi<select id="ftps-history-severity" ${disabled}>${[['all','Tüm seviyeler'],['warning','Uyarı'],['error','Kritik']].map(([v,t])=>`<option value="${v}" ${v===archiveTlsHistoryFilters.severity?'selected':''}>${t}</option>`).join('')}</select></label><button type="button" class="button" data-ftps-history-retry ${disabled}>Yenile</button><span class="tag ${d.fresh&&!archiveTlsHistoryError?'pass':'medium'}">${archiveTlsHistoryError?'Durum alınamadı':d.fresh?'Kaydedici güncel':'Arka plan kaydı kontrol edilmeli'}</span></div><form id="ftps-history-dates" class="ftps-history-dates" aria-label="FTPS geçmişi tarih aralığı"><label>Başlangıç günü<input type="date" id="ftps-history-from" value="${esc(dates.from)}" min="1000-01-01" max="9999-12-31" ${disabled}></label><label>Bitiş günü<input type="date" id="ftps-history-to" value="${esc(dates.to)}" min="1000-01-01" max="9999-12-31" ${disabled}></label><button type="submit" class="button" id="ftps-history-dates-apply" ${disabled}>Aralığı uygula</button><button type="button" class="text-button" id="ftps-history-filter-clear" ${disabled}>Filtreleri temizle</button><span id="ftps-history-dates-status" role="status">${archiveTlsHistoryDateDraft?'Tarih aralığı henüz uygulanmadı.':''}</span></form><p class="ftps-certificate-help">İstanbul saatine göre, seçilen günlerde açık kalan uyarılar gösterilir. Bitiş gününün tamamı dahildir.</p><div class="ftps-history-exports"><button type="button" class="button" data-ftps-history-export="selected" ${busy||archiveTlsHistoryError||archiveTlsHistoryDateDraft||!archiveTlsHistorySelected.size?'disabled':''}>Seçilenleri CSV (${num(archiveTlsHistorySelected.size)})</button><button type="button" class="button" data-ftps-history-export="filtered" ${busy||archiveTlsHistoryError||archiveTlsHistoryDateDraft||!d.total||d.total>50000?'disabled':''}>Filtrelenenleri CSV (${num(d.total)})</button><button type="button" class="text-button" data-ftps-history-selection-clear ${!archiveTlsHistorySelected.size||busy?'disabled':''}>Seçimi temizle</button><span role="status">${archiveTlsHistoryExporting?'CSV hazırlanıyor…':esc(archiveTlsHistoryExportNotice)}</span></div><p class="ftps-certificate-help">Seçimler sayfalar arasında korunur; filtre değişince temizlenir. İşaretli seçim en fazla 1.000, filtrelenen CSV en fazla 50.000 kayıttır.</p><p class="ftps-history-export-error" role="alert" ${archiveTlsHistoryExportError?'':'hidden'}>${esc(archiveTlsHistoryExportError)}</p><p class="ftps-certificate-help" role="status">${archiveTlsHistoryLoading?'Geçmiş güncelleniyor… · ':''}${archiveTlsHistoryError?esc(archiveTlsHistoryError)+' · ':''}${num(d.totals.active)} açık · ${num(d.totals.closed)} kapalı · Kayıt başlangıcı: ${d.coverage_from_at?esc(trTime(d.coverage_from_at,true)):'İlk gözlem bekleniyor'}</p><div class="table-wrap ftps-history-table">${rows.length?table(['<input type="checkbox" id="ftps-history-select-page" aria-label="Bu sayfadaki kayıtları seç" '+disabled+'>','Hedef / uyarı','Seviye','Başlangıç · İstanbul','Tetikleyen eşikler','Kapanış · İstanbul / neden'],rows):'<p class="ftps-certificate-help">Seçilen kapsamda uyarı kaydı yok.</p>'}</div><div class="ftps-history-pagination"><span>${num(d.total)} kayıt · Sayfa ${num(d.page)} / ${num(d.pages)}</span><div><button type="button" class="button" data-ftps-history-page="${d.page-1}" ${busy||d.page<=1?'disabled':''}>← Önceki</button><button type="button" class="button" data-ftps-history-page="${d.page+1}" ${busy||d.page>=d.pages?'disabled':''}>Sonraki →</button></div></div><p class="ftps-certificate-help">Geçmiş, bu özellik açıldıktan sonraki gözlemleri içerir. Arka plan kontrolü yaklaşık dakikada bir yapılır. Eşik, seviye, sertifika veya hedef değişirse önceki dönem kapanış nedeniyle saklanır. Bağlantı ve doğrulama uyarıları gün eşiklerinden bağımsızdır.</p>`;
}
function archiveTlsHistoryRender(){const root=$('#ftps-history-content');if(root){root.innerHTML=archiveTlsHistoryContent();bindArchiveTlsHistoryContent();}}
async function archiveTlsHistoryLoad(){
 const root=$('#ftps-history-content');if(!root)return;const sequence=++archiveTlsHistorySequence;
 if(archiveTlsHistoryData&&(String(archiveTlsHistoryData.filters.target)!==archiveTlsHistoryFilters.target||archiveTlsHistoryData.filters.status!==archiveTlsHistoryFilters.status||archiveTlsHistoryData.page!==archiveTlsHistoryFilters.page||['severity','from','to'].some(k=>(archiveTlsHistoryData.filters[k]??(k==='severity'?'all':''))!==archiveTlsHistoryFilters[k])))archiveTlsHistoryData=null;
 archiveTlsHistoryLoading=true;archiveTlsHistoryError='';archiveTlsHistoryRender();
 try{
  const d=await api('archive_tls_history',false,archiveTlsHistoryQuery());
  if(sequence!==archiveTlsHistorySequence||!root.isConnected)return;
  archiveTlsHistoryData=d;archiveTlsHistoryFilters.page=d.page;archiveTlsHistorySyncUrl();
 }catch(e){if(sequence===archiveTlsHistorySequence&&root.isConnected)archiveTlsHistoryError=e.message;}
 finally{if(sequence===archiveTlsHistorySequence&&root.isConnected){archiveTlsHistoryLoading=false;archiveTlsHistoryRender();}}
}
function bindArchiveTlsHistoryContent(){
 const root=$('#ftps-history-content');if(!root)return;if(typeof bindArchiveTlsViews==='function')bindArchiveTlsViews();
 root.querySelectorAll('[data-ftps-history-retry]').forEach(b=>b.onclick=()=>archiveTlsHistoryLoad());
 for(const [id,key] of [['#ftps-history-target','target'],['#ftps-history-status','status'],['#ftps-history-severity','severity']]){const field=root.querySelector(id);if(field)field.onchange=()=>{archiveTlsHistoryFilters[key]=field.value;archiveTlsHistoryFilters.page=1;archiveTlsHistoryResetSelection();archiveTlsHistorySyncUrl();archiveTlsHistoryLoad();};}
 const form=root.querySelector('#ftps-history-dates'),from=root.querySelector('#ftps-history-from'),to=root.querySelector('#ftps-history-to');
 if(form){
  form.oninput=()=>{from.setCustomValidity('');archiveTlsHistoryDateDraft=from.value===archiveTlsHistoryFilters.from&&to.value===archiveTlsHistoryFilters.to?null:{from:from.value,to:to.value};if(typeof archiveTlsViewsRender==='function')archiveTlsViewsRender();root.querySelector('#ftps-history-dates-status').textContent=archiveTlsHistoryDateDraft?'Tarih aralığı henüz uygulanmadı.':'';for(const b of root.querySelectorAll('[data-ftps-history-export]'))b.disabled=Boolean(archiveTlsHistoryDateDraft)||archiveTlsHistoryLoading||archiveTlsHistoryExporting||Boolean(archiveTlsHistoryError)||(b.dataset.ftpsHistoryExport==='selected'?!archiveTlsHistorySelected.size:!archiveTlsHistoryData.total||archiveTlsHistoryData.total>50000);};
  form.onsubmit=event=>{event.preventDefault();from.setCustomValidity(from.value&&to.value&&from.value>to.value?'Başlangıç tarihi bitişten sonra olamaz.':'');if(!form.reportValidity())return;archiveTlsHistoryFilters.from=from.value;archiveTlsHistoryFilters.to=to.value;archiveTlsHistoryFilters.page=1;archiveTlsHistoryDateDraft=null;archiveTlsHistoryResetSelection();archiveTlsHistorySyncUrl();archiveTlsHistoryLoad();};
 }
 const clear=root.querySelector('#ftps-history-filter-clear');if(clear)clear.onclick=()=>{Object.assign(archiveTlsHistoryFilters,{target:'0',status:'all',severity:'all',from:'',to:'',page:1});archiveTlsHistoryDateDraft=null;archiveTlsHistoryResetSelection();archiveTlsHistorySyncUrl();archiveTlsHistoryLoad();};
 const ids=(archiveTlsHistoryData?.rows||[]).map(r=>String(r.id)),selectPage=root.querySelector('#ftps-history-select-page');
 if(selectPage){selectPage.checked=ids.length>0&&ids.every(id=>archiveTlsHistorySelected.has(id));selectPage.indeterminate=!selectPage.checked&&ids.some(id=>archiveTlsHistorySelected.has(id));selectPage.onchange=()=>archiveTlsHistorySelectionChange(ids,selectPage.checked);}
 root.querySelectorAll('[data-ftps-history-select]').forEach(b=>b.onchange=()=>archiveTlsHistorySelectionChange([b.dataset.ftpsHistorySelect],b.checked));
 root.querySelectorAll('[data-ftps-history-export]').forEach(b=>b.onclick=()=>archiveTlsHistoryExport(b.dataset.ftpsHistoryExport));
 root.querySelectorAll('[data-ftps-history-selection-clear]').forEach(b=>b.onclick=()=>{archiveTlsHistoryResetSelection();archiveTlsHistoryRender();});
 root.querySelectorAll('[data-ftps-history-page]').forEach(b=>b.onclick=()=>{archiveTlsHistoryFilters.page=Number(b.dataset.ftpsHistoryPage);archiveTlsHistorySyncUrl();archiveTlsHistoryLoad();});
}
function bindArchiveTlsHistory(){
 const details=$('#ftps-alert-history');if(!details)return;
 details.ontoggle=()=>{if(details.open===archiveTlsHistoryOpen)return;archiveTlsHistoryOpen=details.open;if(details.open)archiveTlsHistoryLoad();else{++archiveTlsHistorySequence;archiveTlsHistoryLoading=false;if(state.systemFocus==='ftps-alert-history')state.systemFocus='';}archiveTlsHistorySyncUrl();};
 bindArchiveTlsHistoryContent();if(details.open)archiveTlsHistoryLoad();
}
function archiveTlsAccept(data){
 if(data?.settings&&(!archiveTlsSettingsModel||data.settings.revision>=archiveTlsSettingsModel.settings.revision))archiveTlsSettingsModel=data;
 return archiveTlsSettingsModel;
}
function archiveTlsSettingsPanel(data){
 const s=data.settings;if(!s)return '';
 const draft=archiveTlsSettingsDraft||s,conflict=Boolean(archiveTlsSettingsDraft&&archiveTlsSettingsDraft.revision!==s.revision);
 return `<form id="ftps-threshold-form" class="ftps-threshold-form" aria-label="FTPS sertifika uyarı eşikleri"><div class="ftps-threshold-fields"><label for="ftps-warning-days">Uyarı eşiği (gün)<input id="ftps-warning-days" name="warning_days" type="number" min="1" max="3650" step="1" required inputmode="numeric" value="${esc(draft.warning_days)}" ${archiveTlsSettingsSaving?'disabled':''}></label><label for="ftps-critical-days">Kritik uyarı eşiği (gün)<input id="ftps-critical-days" name="critical_days" type="number" min="1" max="3650" step="1" required inputmode="numeric" value="${esc(draft.critical_days)}" ${archiveTlsSettingsSaving?'disabled':''}></label><button id="ftps-threshold-save" type="submit" class="button primary" ${!archiveTlsSettingsDraft||archiveTlsSettingsSaving||conflict?'disabled':''}>${archiveTlsSettingsSaving?'Kaydediliyor…':'Eşikleri kaydet'}</button></div><p class="ftps-threshold-note">1–3.650 gün. Kritik eşik, uyarı eşiğinden büyük olamaz. Kaydedilen eşikler tüm FTPS hedeflerinde hemen uygulanır.</p><div class="ftps-threshold-status"><span id="ftps-threshold-status" role="status">${esc(archiveTlsSettingsDraft?'Kaydedilmemiş değişiklikler':archiveTlsSettingsNotice)}</span><button id="ftps-threshold-reload" class="text-button" type="button" ${conflict?'':'hidden'}>Güncel ayarları yükle</button></div><p id="ftps-threshold-error" class="ftps-threshold-error" role="alert" ${archiveTlsSettingsError||conflict?'':'hidden'}>${esc(archiveTlsSettingsError||(conflict?'Eşikler başka bir oturumda değişti. Güncel ayarları yükleyin.':''))}</p><p class="ftps-threshold-note">Son kayıt: ${esc(trTime(s.updated_at,true))} · ${esc(s.updated_by==='system'?'İlk ayar':s.updated_by)}</p></form>`;
}
function archiveTlsRefreshPanel(){
 const panel=$('#ftps-certificates');if(!panel||state.view!=='system'||!archiveTlsSettingsModel)return;
 panel.outerHTML=archiveTlsSystemPanel(archiveTlsSettingsModel);bindArchiveTlsSettings();
}
function bindArchiveTlsSettings(){
 bindArchiveTlsHistory();
 const form=$('#ftps-threshold-form'),reload=$('#ftps-threshold-reload');if(!form)return;
 const validate=()=>{const warning=form.warning_days.value,critical=form.critical_days.value;form.critical_days.setCustomValidity(Number(critical)>Number(warning)?'Kritik uyarı eşiği, uyarı eşiğinden büyük olamaz.':'');};validate();
 form.oninput=()=>{
  const s=archiveTlsSettingsModel.settings,warning=form.warning_days.value,critical=form.critical_days.value;
  archiveTlsSettingsDraft=warning===String(s.warning_days)&&critical===String(s.critical_days)?null:{warning_days:warning,critical_days:critical,revision:archiveTlsSettingsDraft?.revision??s.revision};
  archiveTlsSettingsError='';archiveTlsSettingsNotice='';validate();const conflict=Boolean(archiveTlsSettingsDraft&&archiveTlsSettingsDraft.revision!==s.revision);
  $('#ftps-threshold-save').disabled=!archiveTlsSettingsDraft||archiveTlsSettingsSaving||conflict;$('#ftps-threshold-status').textContent=archiveTlsSettingsDraft?'Kaydedilmemiş değişiklikler':'';
  $('#ftps-threshold-error').textContent=conflict?'Eşikler başka bir oturumda değişti. Güncel ayarları yükleyin.':'';$('#ftps-threshold-error').hidden=!conflict;reload.hidden=!conflict;
 };
 reload.onclick=async()=>{
  reload.disabled=true;
  try{const data=await api('archive_tls');archiveTlsAccept(data);archiveTlsSettingsDraft=null;archiveTlsSettingsError='';archiveTlsSettingsNotice='Güncel eşikler yüklendi.';archiveTlsRefreshPanel();}
  catch(e){archiveTlsSettingsError=e.message;archiveTlsRefreshPanel();}
  finally{reload.disabled=false;}
 };
 form.onsubmit=async event=>{
  event.preventDefault();validate();if(!archiveTlsSettingsDraft||archiveTlsSettingsSaving||!form.reportValidity())return;
  const body=new FormData();for(const [key,value] of Object.entries(archiveTlsSettingsDraft))body.set(key,String(value));
  archiveTlsSettingsSaving=true;archiveTlsSettingsError='';archiveTlsRefreshPanel();
  try{
   const response=await fetch('/api.php?route=save_archive_tls_settings',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
   if(response.status===401){location.href='/';return;}
   const data=await response.json();archiveTlsAccept(data);if(!response.ok)throw new Error(data.error||'Eşikler kaydedilemedi.');
   archiveTlsSettingsDraft=null;archiveTlsSettingsNotice=data.changed?'Kaydedildi. Uyarılar yeni eşiklerle hesaplanıyor.':'Eşikler zaten güncel.';renderArchiveTlsOverview(data);
  }catch(e){archiveTlsSettingsError=e instanceof TypeError?'Sunucuya ulaşılamadı. Girdiğiniz değerler korunuyor; yeniden deneyin.':e.message;}
  finally{archiveTlsSettingsSaving=false;archiveTlsRefreshPanel();if(state.view==='system')$('#ftps-threshold-save')?.focus({preventScroll:true});}
 };
}
function archiveTlsOverviewLoading(){const root=$('#archive-tls-overview');if(root){root.hidden=true;root.replaceChildren();root.setAttribute('aria-busy','true');}}
function renderArchiveTlsOverview(data){
 const root=$('#archive-tls-overview');if(!root||document.documentElement.dataset.userRole!=='admin')return;
 root.setAttribute('aria-busy','false');const alerts=data?.unavailable?[{code:'status_unavailable',severity:'warning',message:'FTPS sertifika durumu alınamadı. Sistem durumu ekranından yeniden kontrol edin.'}]:data?.alerts||[];
 root.hidden=alerts.length===0;
 root.innerHTML=alerts.map(a=>`<a class="timestamp-health-alert ${a.severity==='error'?'is-error':''}" data-ftps-alert="${esc(a.code)}" href="${esc(archiveTlsAlertLink(a))}"><span aria-hidden="true">!</span><span>${esc(a.message)}${a.destination_id?`<small class="ftps-alert-duration">${a.triggered_at?`Başlangıç: ${esc(trTime(a.triggered_at,true))} · ${esc(archiveTlsElapsed(a.duration_seconds))} süredir açık`:'Başlangıç kaydı bekleniyor'}</small>`:''}</span><b aria-hidden="true">→</b></a>`).join('');
}
function archiveTlsRemaining(target){
 if(target.seconds_remaining===null)return 'Bilinmiyor';
 if(target.seconds_remaining<=0)return 'Süresi doldu';
 return target.seconds_remaining<86400?'24 saatten az':num(target.days_remaining)+' gün';
}
function archiveTlsSystemPanel(data){
 if(data?.settings)data=archiveTlsAccept(data);
 const target='/?view=settings&settings_tab=archive';
 const heading=`<div class="panel-heading"><div><h2 id="ftps-certificates-heading">FTPS sertifikaları</h2><p>Etkin yedekleme hedefleri · güncel sunucu sertifikası · İstanbul saati</p></div><a class="text-link" href="${target}">Yedekleme ayarları →</a></div>`;
 if(!data)return `<section id="ftps-certificates" class="panel ftps-certificates" aria-labelledby="ftps-certificates-heading">${heading}<p class="ftps-certificate-help" role="status">Sertifika durumu alınamadı. Ekranı yenileyip tekrar deneyin.</p></section>`;
 const labels={unknown:'Henüz doğrulanmadı',healthy:'Süresi normal',expiring:'Yakında doluyor',critical:'Kritik süre',expired:'Süresi doldu'};
 const rows=data.targets.map(t=>{
  const label=t.check_code?'Kontrol başarısız':!t.fresh&&t.state==='healthy'?'Kontrol güncel değil':labels[t.state]||'Bilinmiyor';
  const color=['critical','expired'].includes(t.state)||t.check_code?'failed':t.fresh&&t.state==='healthy'?'pass':'medium';
  return `<tr data-ftps-target="${t.id}"><td><strong>${esc(t.name)}</strong><small class="mono">${esc(t.host)}:${esc(t.port)}</small></td><td><span class="tag ${color}">${esc(label)}</span></td><td>${t.expires_at?esc(trTime(t.expires_at,true)):'Bilinmiyor'}</td><td><strong data-ftps-remaining>${esc(archiveTlsRemaining(t))}</strong></td><td>${t.verified_at?esc(trTime(t.verified_at,true)):'Henüz yok'}${!t.fresh&&t.verified_at?'<small>Son bilinen sertifika · yeniden doğrulama bekleniyor</small>':''}</td></tr>`;
 });
 return `<section id="ftps-certificates" class="panel ftps-certificates" aria-labelledby="ftps-certificates-heading" tabindex="-1">${heading}${rows.length?`<div class="table-wrap">${table(['Yedekleme hedefi','Durum','Bitiş tarihi · İstanbul','Kalan süre','Son başarılı kontrol'],rows)}</div>`:'<p class="ftps-certificate-help">Etkin FTPS hedefi bulunmuyor.</p>'}<p class="ftps-certificate-help">Bitişe ${num(data.warning_days)} gün kala uyarı, son ${num(data.critical_days)} günde kritik uyarı gösterilir. Sertifika saatte bir kontrol edilir; sayılar sunucu saatine göre hesaplanır. Seçili cihaz ve tarih aralığından bağımsızdır.</p>${archiveTlsSettingsPanel(data)}${archiveTlsHistoryPanel()}</section>`;
}
