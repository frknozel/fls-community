'use strict';
let investigationSearchData=null,investigationSearchController=null,investigationSearchSequence=0,investigationSearchContext='';
function investigationSearchContextKey(){return JSON.stringify([state.fgDevice,state.period,state.from,state.to,$('#overview-search-scope')?.value||'all']);}
function investigationSearchClear(){
 ++investigationSearchSequence;investigationSearchController?.abort();investigationSearchController=null;investigationSearchData=null;
 const root=$('#investigation-search-results');if(root){root.hidden=true;root.replaceChildren();root.removeAttribute('aria-busy');}
 const button=$('#overview-search-submit');if(button){button.disabled=false;button.textContent='Eşleşmeleri bul →';}
}
function investigationSearchContextChanged(){if(investigationSearchContext&&investigationSearchContext!==investigationSearchContextKey())investigationSearchClear();}
function investigationSearchFreeze(scope){
 const stamp=v=>v.replace(' ','T')+'Z';state.period='custom';state.from=stamp(scope.from_utc);state.to=stamp(scope.to_utc);$('#period').value='custom';uiDateInputs();$('#custom-range').classList.remove('hidden');
}
function investigationSearchTextRecords(mail=false){
 const query=$('#overview-search').value.trim();if(!query)return;
 const kind=$('#overview-search-scope').value;if(investigationSearchData)investigationSearchFreeze(investigationSearchData.scope);
 openFilter({q:query,q_field:mail===true?'mail':'',outcome:({all:'all_blocks',security:'security_block',policy:'policy_deny',local:'local_deny'})[kind]});
}
function investigationSearchRender(data){
 const root=$('#investigation-search-results');root.hidden=false;root.setAttribute('aria-busy','false');
 const scopes={all:'Tüm engeller ve retler',security:'Güvenlik profili engelleri',policy:'Firewall policy retleri',local:'Local deny'};
 const sources=data.sources.map((row,i)=>`<button type="button" class="investigation-search-hit" data-lookup-source="${i}"><span><strong class="mono">${esc(row.ip)}</strong><small>${esc(row.name?'Son gözlenen cihaz adı: '+row.name:'Kaynak IP')}</small></span><span><b>${num(row.records)}</b><small>engel kaydı →</small></span></button>`).join('');
 const targets=data.targets.map((row,i)=>`<button type="button" class="investigation-search-hit" data-lookup-target="${i}"><span><strong>${esc(row.target.label)}</strong><small>${esc(targetKindLabel(row.target.kind))}</small></span><span><b>${num(row.records)}</b><small>engel kaydı →</small></span></button>`).join('');
 root.innerHTML=`<div class="investigation-search-heading"><div><h2>“${esc(data.query)}” için inceleme</h2><p>${esc(scopes[data.scope.kind])} · ${esc(trTime(data.scope.from_utc,true))} → ${esc(trTime(data.scope.to_utc,true))}</p></div><button type="button" class="text-button" data-lookup-clear>Sonuçları kapat</button></div><div class="investigation-search-grid"><section class="panel"><div class="panel-heading"><h3>Kaynak cihazlar</h3><span class="soft-tag">${num(data.sources.length)} / ${num(data.source_total)}</span></div>${sources||'<p class="investigation-search-empty">Bu ad veya IP ile eşleşen kaynak engeli yok.</p>'}</section><section class="panel"><div class="panel-heading"><h3>Hedefler</h3><span class="soft-tag">${num(data.targets.length)} / ${num(data.target_total)}</span></div>${targets||'<p class="investigation-search-empty">Bu alan adı veya IP ile eşleşen hedef engeli yok.</p>'}</section></div><p class="investigation-search-help">Sayılar seçili dönemdeki tekrarları içerir. Her bölümde ilk 8 eşleşme gösterilir.</p><div class="mail-search-shortcuts"><button type="button" class="text-button" data-lookup-mail>E-posta ve dosya alanlarında ara →</button><button type="button" class="text-button" data-lookup-text>Tüm log alanlarında metin ara →</button></div>`;
 root.querySelectorAll('[data-lookup-source]').forEach(b=>b.onclick=()=>{if(investigationSearchContext!==investigationSearchContextKey()){investigationSearchClear();return;}const row=data.sources[Number(b.dataset.lookupSource)];investigationSearchFreeze(data.scope);openSource(row.ip,data.scope.kind);});
 root.querySelectorAll('[data-lookup-target]').forEach(b=>b.onclick=()=>{if(investigationSearchContext!==investigationSearchContextKey()){investigationSearchClear();return;}const row=data.targets[Number(b.dataset.lookupTarget)];investigationSearchFreeze(data.scope);openTarget(row.target,data.scope.kind);});
 root.querySelector('[data-lookup-clear]').onclick=()=>{investigationSearchClear();$('#overview-search').focus();};root.querySelector('[data-lookup-mail]').onclick=()=>investigationSearchTextRecords(true);root.querySelector('[data-lookup-text]').onclick=()=>investigationSearchTextRecords(false);
}
async function investigationSearch(){
 const form=$('#overview-search-form');if(!form.reportValidity())return;
 investigationSearchClear();const sequence=investigationSearchSequence,query=$('#overview-search').value.trim(),scope=$('#overview-search-scope').value,root=$('#investigation-search-results');
 investigationSearchContext=investigationSearchContextKey();investigationSearchController=new AbortController();const signal=investigationSearchController.signal;
 root.hidden=false;root.setAttribute('aria-busy','true');root.innerHTML='<p class="investigation-search-help" role="status">Kaynak cihaz ve hedef eşleşmeleri aranıyor…</p>';
 $('#overview-search-submit').disabled=true;$('#overview-search-submit').textContent='Aranıyor…';
 try{
  const data=await api('investigation_search',false,{lookup:query,lookup_scope:scope},signal);
  if(signal.aborted||sequence!==investigationSearchSequence||investigationSearchContext!==investigationSearchContextKey())return;
  investigationSearchData=data;investigationSearchRender(data);
 }catch(e){if(signal.aborted||sequence!==investigationSearchSequence)return;root.setAttribute('aria-busy','false');root.innerHTML=`<p class="investigation-search-error" role="alert">${esc(e.message)}</p><div class="management-row-actions"><button type="button" class="button" data-lookup-retry>Yeniden dene</button><button type="button" class="text-button" data-lookup-text>Kayıtlarda metin araması aç →</button><button type="button" class="text-button" data-lookup-clear>Sonuçları kapat</button></div>`;root.querySelector('[data-lookup-text]').onclick=()=>investigationSearchTextRecords(false);root.querySelector('[data-lookup-retry]').onclick=investigationSearch;root.querySelector('[data-lookup-clear]').onclick=()=>{investigationSearchClear();$('#overview-search').focus();};}
 finally{if(sequence===investigationSearchSequence){$('#overview-search-submit').disabled=false;$('#overview-search-submit').textContent='Eşleşmeleri bul →';}}
}
function bindInvestigationSearch(){
 const form=$('#overview-search-form');if(!form)return;form.onsubmit=e=>{e.preventDefault();investigationSearch();};
 $('#overview-search').oninput=investigationSearchClear;$('#overview-search-scope').onchange=investigationSearchClear;
 $('#overview-search').onkeydown=e=>{if(e.key==='Escape'){investigationSearchClear();e.preventDefault();}};
}
