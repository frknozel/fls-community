'use strict';

let targetReport=null;
const targetExpanded=new Set();
const targetDimensions={sources:['Erişimi engellenen kaynaklar','kaynak'],policies:['Firewall policy’leri','policy'],profiles:['Güvenlik profilleri','profil'],reasons:['Engelleme gerekçeleri','gerekçe']};
function targetKindLabel(kind){return ({domain:'Alan adı',ip:'Hedef IP',dns_missing:'DNS sorgu adı logda yok',missing:'Hedef alanı logda yok',unknown:'Kayıt bulunmayan hedef'})[kind]||'Hedef';}
function openTarget(target,scope='all',originSource=''){
 if(target.key!==state.targetKey)targetExpanded.clear();
 state.targetKey=target.key;state.targetScope=scope;state.targetOriginSource=validSourceIp(originSource)?originSource:'';
 return setView('target');
}
function targetLoading(){targetReport=null;const root=$('#target-content');root.inert=true;root.setAttribute('aria-busy','true');root.innerHTML='<div class="loading-state">Bu hedefe erişimi engellenen kaynaklar yükleniyor…</div>';}
function targetRecords(filters){
 if(!targetReport)return;
 const stamp=value=>value.replace(' ','T')+'Z';
 state.period='custom';state.from=stamp(targetReport.scope.from_utc);state.to=stamp(targetReport.scope.to_utc);
 $('#period').value='custom';uiDateInputs();$('#custom-range').classList.remove('hidden');openFilter(filters);
}
function targetRankings(){
 const data=targetReport;if(!data)return;
 for(const[dimension,[,unit]]of Object.entries(targetDimensions)){
  const root=$('#target-rank-'+dimension),all=data.rankings[dimension],expanded=targetExpanded.has(dimension),rows=all.slice(0,expanded?10:5),max=all[0]?.records||1;
  const detail=r=>dimension==='sources'?(r.name?'Son gözlenen ad: '+r.name:'Kaynak IP'):dimension==='reasons'?(moduleNames[r.module]||r.module)+' · '+(reasonNames[r.reason_code]||'Logdaki gerekçe'):r.name||(dimension==='profiles'?(r.missing?'Bu kayıtlarda profil belirtilmemiş':'Logdaki profil adı'):'İletilen trafik');
  root.innerHTML=rows.length?rows.map((r,i)=>`${(dimension==='sources'||dimension==='policies'||dimension==='profiles'&&!r.missing||dimension==='reasons')?'<div class="investigation-rank-item">':''}<button type="button" class="block-rank source-rank" data-target-rank="${dimension}:${i}" aria-label="${esc(r.label)}: ${dimension==='reasons'?'gerekçe özetini aç':dimension==='profiles'&&!r.missing?'profil özetini aç':dimension==='policies'?'policy özetini aç':dimension==='sources'&&r.filter.source?'cihaz özetini aç':num(r.records)+' kaydı aç'}" title="${esc(r.label)} · İlk: ${esc(trTime(r.first_event_at,true))} · Son: ${esc(trTime(r.last_event_at,true))}"><span class="block-rank-number">${i+1}</span><span class="block-rank-fact"><strong class="${dimension==='sources'?'mono':''}">${esc(r.label)}</strong><small>${esc(detail(r))}</small><span class="block-rank-track"><i style="width:${Math.max(1,r.records/max*100)}%"></i></span></span><span class="block-rank-count"><b>${num(r.records)}</b><small>%${r.percent.toLocaleString('tr-TR',{maximumFractionDigits:2})}</small></span><span class="block-rank-arrow" aria-hidden="true">→</span></button>${(dimension==='sources'||dimension==='policies'||dimension==='profiles'&&!r.missing||dimension==='reasons')?`<button type="button" class="text-button rank-records" data-target-records="${i}">${num(r.records)} ilgili kaydı aç →</button></div>`:''}`).join(''):empty('Bu aralık ve kapsamda engel kaydı yok.');
  root.querySelectorAll('[data-target-rank]').forEach(button=>button.onclick=()=>{const row=rows[Number(button.dataset.targetRank.split(':')[1])];if(dimension==='sources'&&validSourceIp(row.filter.source))openSource(row.filter.source,data.scope.kind);else if(dimension==='policies')openPolicy(row.filter.policy,row.filter.policy_scope,data.scope.kind);else if(dimension==='profiles'&&!row.missing)openProfile(row.filter.profile,'all',data.scope.kind);else if(dimension==='reasons')openReason(reasonRowRef(row),data.scope.kind);else targetRecords(row.filter);});
  root.querySelectorAll('[data-target-records]').forEach(button=>button.onclick=()=>targetRecords(rows[Number(button.dataset.targetRecords)].filter));
  const panel=root.closest('.panel');panel.querySelector('.source-rank-caption').textContent=all.length?'İlk '+rows.length+' / '+num(data.distinct[dimension])+' '+unit:'Kayıt yok';
  panel.querySelector('[data-target-expand]')?.remove();
  if(all.length>5){const button=document.createElement('button');button.type='button';button.className='rank-more';button.dataset.targetExpand=dimension;button.setAttribute('aria-expanded',String(expanded));button.textContent=expanded?'İlk 5 '+unit+' göster':'Diğer '+(all.length-5)+' '+unit+' göster';button.onclick=()=>{expanded?targetExpanded.delete(dimension):targetExpanded.add(dimension);targetRankings();};panel.append(button);}
 }
}
function renderTarget(data){
 targetReport=data;const root=$('#target-content'),target=data.target,total=data.totals,scopes={all:'Tüm engeller ve retler',security:'Güvenlik profili engelleri',policy:'Firewall policy retleri',local:'Cihaza gelen trafik retleri'};
 root.inert=false;root.setAttribute('aria-busy','false');
 root.innerHTML=`<nav class="investigation-trail" aria-label="İnceleme yolu"><button type="button" class="text-button" id="target-overview">← Genel bakış</button>${state.targetOriginSource?`<button type="button" class="text-button" id="target-origin-source">← Cihaz özeti · ${esc(state.targetOriginSource)}</button>`:''}<span aria-hidden="true">/</span><strong>Hedef özeti</strong></nav><section class="panel source-hero target-hero"><div class="source-identity"><div class="source-device-icon">${icon('target')}</div><div><h2 class="${target.kind==='ip'?'mono':''}" id="target-name">${esc(target.label).replace(/\./g,'.<wbr>')}</h2><p><strong>${esc(targetKindLabel(target.kind))}</strong> · Tüm kaynakların engellenen erişimleri</p></div></div><div class="source-record-total"><strong>${num(total.records)}</strong><span>özgün engel kaydı · ${num(data.distinct.sources)} kaynak</span><button type="button" class="button" id="target-all-records">İlgili kayıtları aç →</button></div><div class="source-range"><span>İncelenen aralık · İstanbul<br><strong>${esc(trTime(data.scope.from_utc,true))} → ${esc(trTime(data.scope.to_utc,true))}</strong></span><span>İlk / son engel<br><strong>${total.records?esc(trTime(total.first_event_at,true))+' → '+esc(trTime(total.last_event_at,true)):'Bu aralıkta engel yok'}</strong></span></div></section><div class="source-ranking-heading"><div><h2>Hedef engel dağılımı</h2><p>Sayılar tekrar eden kayıtları içerir.</p></div><label class="block-scope-label">Engel kapsamı<select id="target-scope" aria-label="Hedef özeti engel kapsamı">${Object.entries(scopes).map(([value,label])=>`<option value="${value}" ${data.scope.kind===value?'selected':''}>${label}</option>`).join('')}</select></label></div><div class="source-ranking-grid">${Object.entries(targetDimensions).map(([dimension,[title]])=>`<section class="panel source-ranking-panel target-ranking-panel" aria-labelledby="target-title-${dimension}"><div class="panel-heading"><h3 id="target-title-${dimension}">${title}</h3><span class="soft-tag source-rank-caption"></span></div><div class="block-rank-list" id="target-rank-${dimension}"></div></section>`).join('')}</div>`;
 $('#target-overview').onclick=()=>setView('overview');
 if($('#target-origin-source'))$('#target-origin-source').onclick=()=>openSource(state.targetOriginSource,data.scope.kind);
 $('#target-all-records').onclick=()=>targetRecords({target_key:target.key,target_label:target.label,outcome:({all:'all_blocks',security:'security_block',policy:'policy_deny',local:'local_deny'})[data.scope.kind]});
 $('#target-scope').onchange=()=>{state.targetScope=$('#target-scope').value;syncUrl('push');load();};targetRankings();
}
