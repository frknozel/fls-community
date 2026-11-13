'use strict';

const uiExpandedRankings=new Set();
const uiRankNames={sources:'kaynak',policies:'policy',profiles:'profil',reasons:'gerekçe'};

function eventFilterDefaults(outcome='security_block'){
 return {target_key:'',target_label:'',source_reason:'',source_reason_label:'',outcome,policy:'',profile:'',module:'',source:'',reason:'',block_reason:'',block_reason_label:'',profile_missing:'',source_missing:'',policy_scope:'',q_field:'mail',q:''};
}
function uiMobileNavigation(open){
 const sidebar=$('.sidebar'),wasOpen=sidebar.classList.contains('mobile-open');
 open=Boolean(open&&innerWidth<=900);sidebar.inert=innerWidth<=900&&!open;
 sidebar.classList.toggle('mobile-open',open);$('.main-shell').inert=open;
 document.body.classList.toggle('navigation-open',open);$('#nav-backdrop').hidden=!open;
 $('#mobile-menu').setAttribute('aria-expanded',String(open));
 if(open&&!wasOpen)(sidebar.querySelector('[aria-current="page"]:not(:disabled)')||sidebar.querySelector('button:not(:disabled),a[href]'))?.focus();
 if(wasOpen&&!open&&innerWidth<=900)$('#mobile-menu').focus();
}
function uiPeriodControls(){
 const live=state.view==='system'&&state.systemTab==='live'||state.view==='fortigate'||state.view==='vpn'&&state.vpnTab==='live'||state.view==='policies'&&state.policyTab==='current';
 const hidden=live||['impact','archive','settings','cold'].includes(state.view);$('#api-device-control').hidden=!['allowed','overview','events','source','target','policy','profile','reason','insights','system','fortigate','policies','vpn','history','impact','ports','cold'].includes(state.view);
 $('#period-control').hidden=hidden;$('#period').classList.toggle('hidden',hidden);
 $('#custom-range').classList.toggle('hidden',hidden||state.period!=='custom');
 const caption=$('#view-scope-label');caption.hidden=!hidden;
 caption.textContent=live?(state.view==='system'?'Sunucunun son ölçümü':'Cihazın son örneği'):state.view==='impact'?'Karşılaştırmanın kendi zaman aralığı':state.view==='settings'?'Çalışma alanı ayarları':state.view==='cold'?'Arşiv kopyasında arama':'Sunucu arşivi';
}
function uiTrafficMode(){
 const control=$('#traffic-mode-control');if(!control)return;
 control.hidden=!['overview','allowed','events','source','target','policy','profile','reason','ports','insights'].includes(state.view);
 control.querySelectorAll('[data-traffic-mode]').forEach(button=>{const active=button.dataset.trafficMode===(state.view==='allowed'?'allowed':'blocked');button.classList.toggle('selected',active);button.setAttribute('aria-pressed',String(active));});
}
function uiWorkspacePanels(){
 uiTrafficMode();
 for(const[group,selected]of [['policy',state.policyTab],['vpn',state.vpnTab],['system',state.systemTab]]){
  document.querySelectorAll('[data-workspace-tab^="'+group+':"]').forEach(button=>{
   const active=button.dataset.workspaceTab===group+':'+selected;
   button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;
   const panel=document.getElementById(button.getAttribute('aria-controls'));if(panel)panel.hidden=!active;
  });
 }
 uiPeriodControls();
 if(typeof uiWorkspaceEnhance==='function')uiWorkspaceEnhance();
}
function uiRankTab(dimension,persist=true){
 state.blockDimension=Object.hasOwn(uiRankNames,dimension)?dimension:'sources';
 document.querySelectorAll('[data-rank-tab]').forEach(button=>{
  const active=button.dataset.rankTab===state.blockDimension;
  button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;
  document.getElementById(button.getAttribute('aria-controls')).hidden=!active;
 });
 if(persist)syncUrl();
}
function uiEnhanceRankings(){
 for(const dimension of Object.keys(uiRankNames)){
  const root=$('#block-top-'+dimension),rows=[...root.querySelectorAll('[data-block-rank]')],expanded=uiExpandedRankings.has(dimension),panel=root.closest('.panel');
  rows.forEach((row,i)=>{row.hidden=i>=5&&!expanded;});
  panel.querySelector('[data-rank-expand]')?.remove();
  const tag=panel.querySelector('.soft-tag');if(tag)tag.textContent=rows.length?'İlk '+Math.min(rows.length,expanded?10:5):'Kayıt yok';
  if(rows.length>5){
   const button=document.createElement('button');button.type='button';button.className='rank-more';button.dataset.rankExpand=dimension;
   button.textContent=expanded?'İlk 5 '+uiRankNames[dimension]+' göster':'Diğer '+(rows.length-5)+' '+uiRankNames[dimension]+' göster';
   button.setAttribute('aria-expanded',String(expanded));button.onclick=()=>{expanded?uiExpandedRankings.delete(dimension):uiExpandedRankings.add(dimension);uiEnhanceRankings();};panel.append(button);
  }
 }
 uiRankTab(state.blockDimension,false);
}
function uiFilterFacts(){
 const f=state.filters,labels=[];
 if(f.outcome!=='security_block')labels.push(['outcome',({'':'Tüm kayıtlar',all_blocks:'Tüm engeller ve retler',security_block:'Güvenlik profili engelleri',rating_error:'FortiGuard hataları',local_deny:'Cihaza gelen trafik reddi',policy_deny:'Firewall policy reddi',observed:'Diğer gözlemler'})[f.outcome]||f.outcome]);
 if(f.target_key)labels.push(['target_key','Hedef: '+(f.target_label||'Seçilen hedef')]);
 if(f.source_reason)labels.push(['source_reason',f.source_reason_label||'Seçilen engelleme gerekçesi']);
 if(f.source)labels.push(['source','Kaynak: '+f.source]);
 if(f.module)labels.push(['module',moduleNames[f.module]||f.module]);
 if(f.policy)labels.push(['policy','Policy #'+f.policy]);
 if(f.profile)labels.push(['profile','Profil: '+f.profile]);
 if(f.q)labels.push(['q','Arama: '+f.q]);
 if(f.block_reason)labels.push(['block_reason',f.block_reason_label||'Seçilen engelleme gerekçesi']);
 if(f.reason)labels.push(['reason',reasonNames[f.reason]||f.reason]);
 if(f.profile_missing)labels.push(['profile_missing','Profil alanı yok']);
 if(f.source_missing)labels.push(['source_missing','Kaynak IP alanı yok']);
 if(f.policy_scope)labels.push(['policy_scope',f.policy_scope==='local'?'Cihaza gelen trafik':'İletilen trafik']);
 return labels;
}
function uiResponsiveFilters(){
 const panel=$('#event-filter-panel'),mode=innerWidth<=600?'mobile':'desktop';if(panel.dataset.mode!==mode){panel.dataset.mode=mode;panel.open=mode==='desktop';}
}
function uiEventContext(){
 const facts=uiFilterFacts(),f=state.filters;uiResponsiveFilters();$('#filter-panel-count').textContent=facts.length?num(facts.length)+' etkin':'';
 $('#filter-context').innerHTML=facts.map(([key,label])=>`<button type="button" class="filter-chip" data-filter-remove="${key}" aria-label="${esc(label)} filtresini kaldır"><span>${esc(label)}</span><span aria-hidden="true">×</span></button>`).join('');
 $('#filter-context').querySelectorAll('[data-filter-remove]').forEach(button=>button.onclick=()=>{
  const key=button.dataset.filterRemove;state.filters[key]=key==='outcome'?'security_block':'';
  if(key==='block_reason')state.filters.block_reason_label='';if(key==='target_key')state.filters.target_label='';if(key==='source_reason')state.filters.source_reason_label='';state.page=1;syncFilters();syncUrl();load();
 });
 const subject=f.source?'Kaynak '+f.source:f.profile?'Profil '+f.profile:f.policy?'Policy #'+f.policy:f.q?'Arama sonuçları':f.outcome==='security_block'?'Güvenlik engelleri':f.outcome==='all_blocks'?'Tüm engeller':'Seçili kayıtlar';
 $('#investigation-trail').innerHTML=`<button type="button" class="text-button" id="back-to-overview">← Genel bakış</button><span aria-hidden="true">/</span><strong>${esc(subject)}</strong>`;
 $('#back-to-overview').onclick=()=>setView('overview');
 if(f.source&&validSourceIp(f.source)){const b=document.createElement('button');b.type='button';b.className='text-button';b.id='back-to-source';b.textContent='← Cihaz özeti';b.onclick=()=>openSource(f.source,sourceScopeFor(f.outcome));$('#investigation-trail').append(b);}
 if(f.policy!==''&&f.policy_scope){const b=document.createElement('button');b.type='button';b.className='text-button';b.id='back-to-policy';b.textContent='← Policy özeti';b.onclick=()=>openPolicy(f.policy,f.policy_scope,sourceScopeFor(f.outcome));$('#investigation-trail').append(b);}
 if(f.profile!==''){const b=document.createElement('button');b.type='button';b.className='text-button';b.id='back-to-profile';b.textContent='← Profil özeti';b.onclick=()=>openProfile(f.profile,f.module||'all',sourceScopeFor(f.outcome));$('#investigation-trail').append(b);}
 if(f.source_reason||f.block_reason){const b=document.createElement('button');b.type='button';b.className='text-button';b.id='back-to-reason';b.textContent='← Gerekçe özeti';b.onclick=()=>openReason(reasonRowRef({filter:f}),sourceScopeFor(f.outcome));$('#investigation-trail').append(b);}
 if(f.target_key){const b=document.createElement('button');b.type='button';b.className='text-button';b.id='back-to-target';b.textContent='← Hedef özeti';b.onclick=()=>openTarget({key:f.target_key},sourceScopeFor(f.outcome),f.source);$('#investigation-trail').append(b);}
 const advanced=$('#event-advanced'),context=f.policy+'|'+f.profile;if(advanced.dataset.context!==context){advanced.dataset.context=context;if(f.policy||f.profile)advanced.open=true;}
 const shortcuts=[['','Tüm modüller'],['virus','Antivirüs'],['webfilter','Web filtresi'],['dns','DNS'],['app-ctrl','Uygulamalar'],['ips','IPS'],['ssl','SSL / TLS']];
 $('#event-module-shortcuts').innerHTML=shortcuts.map(([kind,label])=>`<button type="button" class="module-shortcut ${f.module===kind?'selected':''}" data-quick-module="${kind}" aria-pressed="${f.module===kind}">${label}</button>`).join('');
 $('#event-module-shortcuts').querySelectorAll('[data-quick-module]').forEach(button=>button.onclick=()=>{
  state.filters.module=button.dataset.quickModule;state.filters.outcome='security_block';
  for(const key of ['reason','block_reason','block_reason_label'])state.filters[key]='';
  state.page=1;syncFilters();syncUrl();load();
 });
}
function uiAnnotateEvents(){
 const labels=['Son olay / tekrar','Sonuç / modül','Kaynak','Hedef / uygulama','Policy ve profil','Engelleme nedeni','Ayrıntı'];
 $('#events-table').querySelectorAll('tr[data-event]').forEach(row=>[...row.cells].forEach((cell,i)=>cell.dataset.cellLabel=labels[i]));
 $('#events-table').querySelectorAll('[data-event-source]').forEach(button=>button.onclick=event=>{
  event.stopPropagation();if(validSourceIp(button.dataset.eventSource))openSource(button.dataset.eventSource,sourceScopeFor(state.filters.outcome));else openFilter({...state.filters,source:button.dataset.eventSource});
 });
 uiEventContext();
}
function uiReveal(element){
 for(let parent=element?.parentElement;parent;parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;
 element?.scrollIntoView({block:'start'});
}
function uiOrganizeEvent(e,d){
 const root=$('#detail-content'),core=root.querySelector(':scope > .detail-grid'),path=root.querySelector('.decision-path');
 const technicalFacts=document.createElement('div');technicalFacts.className='detail-grid';
 if(core&&path){const boxes=[...core.children];[0,1,6,7].forEach(i=>technicalFacts.append(boxes[i]));core.replaceChildren(...[2,3,4,5].map(i=>boxes[i]));root.querySelector('.decision-box').after(core);}
 root.querySelector('.decision-box').classList.toggle('neutral',!['security_block','policy_deny','local_deny'].includes(e.outcome)&&e.utm_action!=='block');
 const meta=document.createElement('p');meta.className='detail-record-meta';meta.textContent='Olay #'+e.id+' · '+trTime(e.event_at,true);root.prepend(meta);
 const actions=document.createElement('div');actions.className='detail-drilldowns';
 if(state.view==='allowed'&&typeof allowedDetailActions==='function'){allowedDetailActions(actions,e);}else{
 if(e.srcip){const source=document.createElement('button');source.className='button';source.textContent='Cihaz özetini aç →';source.onclick=()=>{$('#event-dialog').close();if(validSourceIp(e.srcip))openSource(e.srcip,'all');else openFilter({source:e.srcip,outcome:'all_blocks'});};actions.append(source);}
 if(e.profile||e.policyid>0){const policy=document.createElement('button');policy.className='text-button';policy.textContent=e.profile?'Policy ve profil ayarları →':'Policy ayarları →';policy.onclick=()=>{$('#event-dialog').close();fgPolicySearch=e.profile||String(e.policyid);state.policyTab='current';setView('policies');};actions.append(policy);}
 {const policy=document.createElement('button');policy.type='button';policy.className='button';policy.textContent='Policy özetini aç →';policy.dataset.detailPolicy=String(e.policyid);policy.onclick=()=>{$('#event-dialog').close();openPolicy(e.policyid,e.subtype==='local'?'local':'forward',sourceScopeFor(e.outcome));};actions.append(policy);}
 if(e.profile!==''){const profile=document.createElement('button');profile.type='button';profile.className='button';profile.textContent='Profil özetini aç →';profile.dataset.detailProfile=e.profile;profile.onclick=()=>{$('#event-dialog').close();openProfile(e.profile,e.subtype,sourceScopeFor(e.outcome));};actions.append(profile);}
 if(e.block_explanation){const reason=document.createElement('button');reason.type='button';reason.className='button';reason.textContent='Gerekçe özetini aç →';reason.dataset.detailReason=e.block_explanation.reference;reason.onclick=()=>{$('#event-dialog').close();openReason(e.block_explanation.reference,sourceScopeFor(e.outcome));};actions.append(reason);}
 if(e.target){const target=document.createElement('button');target.type='button';target.className='button';target.textContent='Hedef özetini aç →';target.dataset.detailTarget=e.target.key;target.onclick=()=>{$('#event-dialog').close();openTarget(e.target,sourceScopeFor(e.outcome),e.srcip);};actions.append(target);}

 }
 core?.after(actions);
 const fold=(label,description,nodes,id)=>{
  const present=nodes.filter(Boolean);if(!present.length)return;
  const detail=document.createElement('details');detail.className='detail-disclosure';detail.id=id;
  const summary=document.createElement('summary'),title=document.createElement('span'),hint=document.createElement('small');title.textContent=label;hint.textContent=description;summary.append(title,hint);detail.append(summary);
  const content=document.createElement('div');content.className='detail-disclosure-content';present.forEach(node=>content.append(node));detail.append(content);root.append(detail);return detail;
 };
 const group=d.traffic_group||d.security_group||d.av_group;
 fold('Tekrarlar ve ilişkili kayıtlar',group?num(group.total_records)+' kayıt · ilk / son görülme ve oturum ilişkisi':'Aynı oturumdaki diğer kayıtlar',[...root.querySelectorAll(':scope > .av-group-card'),root.querySelector('[data-detail-section="related"]')],'detail-repeats');
 fold('Alıcı notları',num(e.note_count)+' kayıtlı not · antispam doğrulaması',[root.querySelector('#event-notes')],'detail-notes');
 fold('Policy ve profil karşılaştırması','Olay çevresindeki gözlemler ve bugünkü ayarlar',[root.querySelector('#event-config-history'),root.querySelector('#event-current-config')],'detail-config');
 fold('Ham kayıt ve teknik alanlar',d.raw_verified?'SHA-256 doğrulandı · özgün kayıt ve ayrıştırılan alanlar':'Ham kayıt doğrulaması kontrol edilmeli',[technicalFacts,root.querySelector('[data-detail-section="raw"]'),root.querySelector('[data-detail-section="fields"]')],'detail-technical');
}
function uiBindTabs(root){
 root.querySelectorAll('[role="tablist"]').forEach(list=>list.addEventListener('keydown',event=>{
  const buttons=[...list.querySelectorAll('[role="tab"]')],index=buttons.indexOf(event.target);if(index<0||!['ArrowRight','ArrowLeft','Home','End'].includes(event.key))return;
  const next=event.key==='Home'?0:event.key==='End'?buttons.length-1:(index+(event.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;
  event.preventDefault();buttons[next].focus();buttons[next].click();
 }));
}
function bindInterface(){
 const caption=document.createElement('span');caption.id='view-scope-label';caption.className='view-scope-label';$('.heading-actions').prepend(caption);
 bindInvestigationSearch();
 $('#nav-backdrop').onclick=()=>uiMobileNavigation(false);
 window.addEventListener('resize',()=>{uiMobileNavigation($('.sidebar').classList.contains('mobile-open'));uiResponsiveFilters();});
 document.addEventListener('keydown',event=>{if(!$('.sidebar').classList.contains('mobile-open'))return;
  if(event.key==='Escape'){event.preventDefault();uiMobileNavigation(false);return;}
  if(event.key==='Tab'){
   const items=[...$('.sidebar').querySelectorAll('a[href],button:not(:disabled),select,input')].filter(el=>!el.hidden&&el.getClientRects().length),first=items[0],last=items.at(-1);
   if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}
  }});
 document.querySelectorAll('[data-rank-tab]').forEach(button=>button.onclick=()=>uiRankTab(button.dataset.rankTab));
 document.querySelectorAll('[data-workspace-tab]').forEach(button=>button.onclick=()=>{
  const[group,tab]=button.dataset.workspaceTab.split(':');state[group==='policy'?'policyTab':group==='system'?'systemTab':'vpnTab']=tab;if(group==='system')state.systemFocus='';uiWorkspacePanels();syncUrl('push');
 });
 uiBindTabs(document);uiRankTab(state.blockDimension,false);uiWorkspacePanels();
 history.scrollRestoration='manual';
 window.addEventListener('popstate',async()=>{
  const y=history.state?.scrollY||0;for(const selector of ['#workspace-menu-dialog','#event-dialog','#profile-dialog','#history-dialog','#management-dialog','#cold-event-dialog'])$(selector).close();
  Object.assign(state,initialState());$('#period').value=state.period;uiDateInputs();
  $('#group-av').checked=state.groupAv;$('#group-security').checked=state.groupSecurity;$('#group-traffic').checked=state.groupTraffic;
  syncFilters();await setView(state.view,false);window.scrollTo(0,y);
 });
}
