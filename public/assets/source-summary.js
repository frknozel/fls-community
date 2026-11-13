'use strict';

let sourceReport=null;
const sourceExpanded=new Set();
const sourceDimensions={targets:['Engellenen hedefler','hedef'],policies:['Firewall policy’leri','policy'],profiles:['Güvenlik profilleri','profil'],reasons:['Engelleme gerekçeleri','gerekçe']};
function validSourceIp(value){
 if(typeof value!=='string'||!value||/[\s%/\\?#@]/.test(value))return false;
 if(value.includes(':')){try{return new URL('http://['+value+']/').hostname.startsWith('[');}catch{return false;}}
 return /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)&&value.split('.').every(part=>Number(part)<=255);
}
function sourceScopeFor(outcome){return ({security_block:'security',policy_deny:'policy',local_deny:'local'})[outcome]||'all';}
function openSource(ip,scope='all'){
 if(ip!==state.sourceIp)sourceExpanded.clear();
 state.sourceIp=ip;state.sourceScope=scope;return setView('source');
}
function uiDateInputs(){
 const local=value=>{
  if(!value||!/(Z|[+-]\d\d:\d\d)$/.test(value))return value;
  const date=new Date(value);if(Number.isNaN(date.getTime()))return '';
  return new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Istanbul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).format(date).replace(' ','T');
 };
 $('#from').value=local(state.from);$('#to').value=local(state.to);
}
function sourceLoading(){sourceReport=null;const root=$('#source-content');root.inert=true;root.setAttribute('aria-busy','true');root.innerHTML='<div class="loading-state">Cihazın engellenen erişimleri yükleniyor…</div>';}
function sourceRecords(filters){
 if(!sourceReport)return;
 // Freeze the window used by the ranking, including its exclusive upper boundary.
 const stamp=value=>value.replace(' ','T')+'Z';
 state.period='custom';state.from=stamp(sourceReport.scope.from_utc);state.to=stamp(sourceReport.scope.to_utc);
 $('#period').value='custom';uiDateInputs();$('#custom-range').classList.remove('hidden');
 openFilter(filters);
}
function sourceRankings(){
 const data=sourceReport;if(!data)return;
 for(const[dimension,[,unit]]of Object.entries(sourceDimensions)){
  const root=$('#source-rank-'+dimension),all=data.rankings[dimension],expanded=sourceExpanded.has(dimension),rows=all.slice(0,expanded?10:5),max=all[0]?.records||1;
  const detail=r=>dimension==='targets'?({domain:'Alan adı',ip:'Hedef IP',dns_missing:'DNS · çözümleyici adresi hedef olarak sayılmaz',missing:'Hedef belirtilmemiş'})[r.kind]:dimension==='reasons'?(moduleNames[r.module]||r.module)+' · '+(reasonNames[r.reason_code]||'Logdaki gerekçe'):r.name||(dimension==='profiles'?(r.missing?'Bu kayıtlarda profil belirtilmemiş':'Logdaki profil adı'):'İletilen trafik');
  root.innerHTML=rows.length?rows.map((r,i)=>`${(dimension==='targets'||dimension==='policies'||dimension==='profiles'&&!r.missing||dimension==='reasons')?'<div class="investigation-rank-item">':''}<button type="button" class="block-rank source-rank" data-source-rank="${dimension}:${i}" aria-label="${esc(r.label)}: ${dimension==='reasons'?'gerekçe özetini aç':dimension==='profiles'&&!r.missing?'profil özetini aç':dimension==='policies'?'policy özetini aç':dimension==='targets'?'hedef özetini aç':num(r.records)+' kaydı aç'}" title="${esc(r.label)} · İlk: ${esc(trTime(r.first_event_at,true))} · Son: ${esc(trTime(r.last_event_at,true))}"><span class="block-rank-number">${i+1}</span><span class="block-rank-fact"><strong class="${dimension==='targets'&&r.kind==='ip'?'mono':''}">${esc(r.label)}</strong><small>${esc(detail(r))}</small><span class="block-rank-track"><i style="width:${Math.max(1,r.records/max*100)}%"></i></span></span><span class="block-rank-count"><b>${num(r.records)}</b><small>%${r.percent.toLocaleString('tr-TR',{maximumFractionDigits:2})}</small></span><span class="block-rank-arrow" aria-hidden="true">→</span></button>${(dimension==='targets'||dimension==='policies'||dimension==='profiles'&&!r.missing||dimension==='reasons')?`<button type="button" class="text-button rank-records" data-source-records="${i}">Bu cihazın ${num(r.records)} kaydını aç →</button></div>`:''}`).join(''):empty('Bu aralık ve kapsamda engel kaydı yok.');
  root.querySelectorAll('[data-source-rank]').forEach(button=>button.onclick=()=>{const row=rows[Number(button.dataset.sourceRank.split(':')[1])];if(dimension==='targets')openTarget(row.target,data.scope.kind,data.source.ip);else if(dimension==='policies')openPolicy(row.filter.policy,row.filter.policy_scope,data.scope.kind);else if(dimension==='profiles'&&!row.missing)openProfile(row.filter.profile,'all',data.scope.kind);else if(dimension==='reasons')openReason(reasonRowRef(row),data.scope.kind);else sourceRecords(row.filter);});
  root.querySelectorAll('[data-source-records]').forEach(button=>button.onclick=()=>sourceRecords(rows[Number(button.dataset.sourceRecords)].filter));
  const panel=root.closest('.panel');panel.querySelector('.source-rank-caption').textContent=all.length?'İlk '+Math.min(rows.length,all.length)+' / '+num(data.distinct[dimension])+' '+unit:'Kayıt yok';
  panel.querySelector('[data-source-expand]')?.remove();
  if(all.length>5){const button=document.createElement('button');button.type='button';button.className='rank-more';button.dataset.sourceExpand=dimension;button.setAttribute('aria-expanded',String(expanded));button.textContent=expanded?'İlk 5 '+unit+' göster':'Diğer '+(all.length-5)+' '+unit+' göster';button.onclick=()=>{expanded?sourceExpanded.delete(dimension):sourceExpanded.add(dimension);sourceRankings();};panel.append(button);}
 }
}
function renderSource(data){
 sourceReport=data;const root=$('#source-content'),ip=data.source.ip,names=data.source.observed_names.map(r=>r.name),total=data.totals,scopes={all:'Tüm engeller ve retler',security:'Güvenlik profili engelleri',policy:'Firewall policy retleri',local:'Cihaza gelen trafik retleri'};
 root.inert=false;root.setAttribute('aria-busy','false');
 root.innerHTML=`<nav class="investigation-trail" aria-label="İnceleme yolu"><button type="button" class="text-button" id="source-overview">← Genel bakış</button><span aria-hidden="true">/</span><strong>Cihaz özeti</strong></nav><section class="panel source-hero"><div class="source-identity"><div class="source-device-icon">${icon('users')}</div><div><h2 class="mono" id="source-ip">${esc(ip)}</h2>${names.length?`<p class="source-names"><strong>${esc(names[0])}</strong><span>Son kayıtlarda gözlenen ad${names.length>1?'lar: '+esc(names.join(' / ')):''}</span></p>`:'<p>Son kayıtlarda cihaz adı belirtilmemiş.</p>'}</div></div><div class="source-record-total"><strong>${num(total.records)}</strong><span>özgün engel kaydı</span><button type="button" class="button" id="source-all-records">İlgili kayıtları aç →</button></div><div class="source-range"><span>İncelenen aralık · İstanbul<br><strong>${esc(trTime(data.scope.from_utc,true))} → ${esc(trTime(data.scope.to_utc,true))}</strong></span><span>İlk / son engel<br><strong>${total.records?esc(trTime(total.first_event_at,true))+' → '+esc(trTime(total.last_event_at,true)):'Bu aralıkta engel yok'}</strong></span></div></section><div class="source-ranking-heading"><div><h2>Kaynak engel dağılımı</h2><p>Sayılar tekrar eden kayıtları içerir.</p></div><label class="block-scope-label">Engel kapsamı<select id="source-scope" aria-label="Cihaz özeti engel kapsamı">${Object.entries(scopes).map(([value,label])=>`<option value="${value}" ${data.scope.kind===value?'selected':''}>${label}</option>`).join('')}</select></label></div><div class="source-ranking-grid">${Object.entries(sourceDimensions).map(([dimension,[title]])=>`<section class="panel source-ranking-panel" aria-labelledby="source-title-${dimension}"><div class="panel-heading"><h3 id="source-title-${dimension}">${title}</h3><span class="soft-tag source-rank-caption"></span></div><div class="block-rank-list" id="source-rank-${dimension}"></div></section>`).join('')}</div>`;
 $('#source-overview').onclick=()=>setView('overview');
 $('#source-all-records').onclick=()=>sourceRecords({source:ip,outcome:({all:'all_blocks',security:'security_block',policy:'policy_deny',local:'local_deny'})[data.scope.kind]});
 $('#source-scope').onchange=()=>{state.sourceScope=$('#source-scope').value;syncUrl('push');load();};
 sourceRankings();
}
