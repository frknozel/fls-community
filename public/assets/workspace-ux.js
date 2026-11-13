'use strict';

// Local destinations keep navigation searchable without fetching report data.
const workspacePages={
 overview:{description:'Engelleri kaynak, hedef, policy ve gerekçeye göre inceleyin; ayrıntılı kayıtlara buradan geçin.',keywords:'anasayfa özet dashboard engellenenler',related:['events','allowed','ports']},
 allowed:{description:'İzin verilen oturumları kaynak ve hedefe göre inceleyin; bir grubu açarak oturum kayıtlarını görün.',keywords:'izin verilenler başarılı oturum trafik',related:['overview','events','cold']},
 events:{description:'Engelleri ve diğer kayıtları arayın, filtreleyin; bir kaydı açarak kararın gerekçesini görün.',keywords:'engellenenler log kayıt eposta antivirüs arama csv',related:['overview','ports','cold']},
 cold:{description:'Arşiv kopyalarında tarih ve kaynak seçerek ayrıntılı kayıt arayın. Sonuçlar elle yenilenir.',keywords:'ham log ayrıntılı arşiv sorgu kopya',related:['events','archive']},
 ports:{description:'Engellenen hedef portlarını karşılaştırın; bir grubu açarak kaynakları ve kayıtları inceleyin.',keywords:'port engelleri servis tcp udp',related:['events','overview']},
 vpn:{description:'Güncel VPN bağlantılarını veya seçilen aralıktaki kullanıcı geçmişini inceleyin.',keywords:'vpn kullanıcıları tünel ssl ipsec oturum',related:['fortigate','events']},
 insights:{description:'Seçili kayıtlardan üretilen ipuçlarını açarak ilgili kaynak ve engelleri inceleyin.',keywords:'bulgu öneri analiz ipucu',related:['overview','events']},
 policies:{description:'Cihazın güncel policy ve profillerini, loglarda gözlenen kullanımlarıyla ayrı sekmelerde inceleyin.',keywords:'policy politika kural profil yapılandırma',related:['history','impact','events']},
 history:{description:'Policy ve profil değişikliklerini bulun; bir değişikliği açarak önceki ve sonraki değerleri görün.',keywords:'ayar geçmişi yapılandırma değişiklik',related:['policies','impact']},
 impact:{description:'Bir ayar değişikliği seçin; öncesindeki ve sonrasındaki engelleri aynı sürelerle karşılaştırın.',keywords:'önce sonra karşılaştır etki artış azalış',related:['history','policies','overview']},
 fortigate:{description:'Seçili FortiGate’in son API ölçümünü, kaynak kullanımını ve bağlantı durumunu inceleyin.',keywords:'canlı cihaz cpu bellek performans api',related:['vpn','policies','device-settings']},
 system:{description:'Log alımını, sunucu kaynaklarını ve işleme kuyruğunu izleyin; her bölümün ayrıntıları ayrı sekmededir.',keywords:'sunucu alıcı kuyruk backlog kaynak disk servis',admin:true,related:['archive','archive-settings','product-settings']},
 archive:{description:'İmzalı arşivlerin bütünlüğünü denetleyin; zaman damgası ve aktarım durumlarını inceleyin.',keywords:'imza bütünlük zaman damgası aktarım ftps',admin:true,related:['archive-settings','cold','system']},
 settings:{description:'FortiGate cihazlarını, API anahtarlarını ve çalışma alanı ayarlarını ilgili bölümden yönetin.',keywords:'ayarlar yönetim cihaz ekle anahtar kullanıcı yedekleme lisans',related:['device-settings','user-settings','archive-settings','disk-settings','product-settings']},
 source:{description:'Bu kaynak cihazın engellerini hedef, policy, profil ve gerekçeye göre inceleyin.',parent:'overview',related:['events','ports']},
 target:{description:'Bu hedefe yönelik engelleri kaynak ve gerekçeye göre inceleyin.',parent:'overview',related:['events','ports']},
 policy:{description:'Bu policy ile ilişkili engelleri ve loglarda gözlenen kullanımını inceleyin.',parent:'policies',related:['events','history']},
 profile:{description:'Bu güvenlik profiliyle ilişkili engelleri kaynak ve gerekçeye göre inceleyin.',parent:'policies',related:['events','history']},
 reason:{description:'Bu engelleme gerekçesine ait kaynakları, hedefleri ve kayıtları inceleyin.',parent:'overview',related:['events','ports']}
};
const workspaceActions={
 'device-settings':{title:'FortiGate ve API anahtarları',description:'Cihaz seçin; anahtar ekleyin, düzenleyin veya silin.',keywords:'cihaz fortigate api anahtarı sil token bağlantı',view:'settings',tab:'connections',admin:true},
 'new-device':{title:'Yeni FortiGate ekle',description:'Yeni cihazın bağlantı bilgilerini tanımlayın.',keywords:'cihaz ekle yeni fortigate 50g 60f',view:'settings',tab:'connections',action:'new-device',admin:true},
 'user-settings':{title:'Kullanıcı hesapları',description:'Hesapları ve cihaz erişimlerini yönetin.',keywords:'kullanıcı parola yetki hesap erişim',view:'settings',tab:'users',admin:true},
 'archive-settings':{title:'Arşiv ve yedekleme ayarları',description:'Arşiv aktarım hedeflerini ve sertifika uyarılarını yönetin.',keywords:'ftps ftp yedekleme aktarım hedef sertifika',view:'settings',tab:'archive',admin:true},
 'disk-settings':{title:'Disk ve depolama',description:'SSD, ana depo ve isteğe bağlı saatlik rsync eşleme diskini yönetin.',keywords:'disk ssd hdd depolama rsync eşleme aynalama kapasite bölüm partition',view:'settings',tab:'storage',admin:true},
 'product-settings':{title:'Ürün ve saklama ayarları',description:'Lisans, saklama süresi ve arşiv kopyalarını yönetin.',keywords:'lisans saklama retention depolama ürün',view:'settings',tab:'product',admin:true}
};
let workspaceMenuReturn=null,workspaceLoadingTimer=null,workspaceNavigationRevision=0;
function workspaceIsAdmin(){return document.documentElement.dataset.userRole==='admin';}
function workspaceDestination(id){const item=workspaceActions[id]||workspacePages[id];if(!item||item.admin&&!workspaceIsAdmin())return null;return id==='settings'&&!workspaceIsAdmin()?{...item,description:'Hesabınızı ve görünüm tercihlerinizi yönetin.'}:item;}
function workspaceDestinations(){return [...Object.keys(workspacePages).filter(id=>!workspacePages[id].parent),...Object.keys(workspaceActions)].filter(id=>workspaceDestination(id)&&(state.fgDevice||workspaceActions[id]||['settings','system','archive'].includes(id)));}
function workspaceTitle(id){return workspaceActions[id]?.title||titles[id]?.[0]||'';}
function workspaceNormalize(text){return String(text).toLocaleLowerCase('tr-TR').normalize('NFD').replace(/\p{Diacritic}/gu,'').replace(/ı/g,'i');}
function workspaceLink(id){return `<button type="button" class="workspace-destination" data-workspace-destination="${id}">${esc(workspaceTitle(id))}<span aria-hidden="true">→</span></button>`;}
async function workspaceNavigate(id){
 const item=workspaceDestination(id);if(!item)return;
 const revision=++workspaceNavigationRevision;
 const dialog=$('#workspace-menu-dialog');if(dialog.open)dialog.close();
 $('#workspace-related').open=false;
 if(item.tab){state.settingsTab=item.tab;state.setupDevice='';if(item.tab==='connections')state.settingsDeviceTab='keys';}
 await setView(item.view||id,true);
 if(revision!==workspaceNavigationRevision||state.view!==(item.view||id)||item.tab&&state.settingsTab!==item.tab||document.querySelector('dialog[open]'))return;
 if(item.action==='new-device'&&$('#error-banner').classList.contains('hidden'))document.querySelector('[data-connection-new]')?.click();
 else $('#page-title').focus({preventScroll:true});
}
function workspaceRange(){
 const local=value=>{if(!/(Z|[+-]\d\d:\d\d)$/.test(value))return value.replace('T',' ');const date=new Date(value);return Number.isNaN(date.getTime())?value:new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Istanbul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).format(date);};
 if(state.period==='custom')return local(state.from||'Başlangıç seçilmedi')+(state.to?' – '+local(state.to):' – şimdi')+' · İstanbul';
 return $('#period option:checked')?.textContent||'Seçili zaman aralığı';
}
function uiWorkspaceEnhance(){
 const page=workspacePages[state.view]||workspacePages.overview;
 $('#workspace-page-description').textContent=workspaceDestination(state.view)?.description||page.description;
 const device=$('#api-device option:checked')?.textContent||'Cihaz seçilmedi';
 const live=state.view==='fortigate'||state.view==='vpn'&&state.vpnTab==='live'||state.view==='policies'&&state.policyTab==='current';
 const scope=state.view==='settings'?'Çalışma alanı yönetimi':state.view==='archive'?'Sunucu arşivi · tüm cihazlar':state.view==='system'?'Log sunucusu · '+(state.systemTab==='live'?'son ölçüm':workspaceRange()):device+' · '+(state.view==='cold'?'Arşiv ekranında seçilen aralık':state.view==='impact'?'Seçilen değişikliğin öncesi ve sonrası':live?'Son API örneği':workspaceRange());
 $('#workspace-page-context').textContent=scope;
 $('#workspace-page-back').hidden=!page.parent;
 if(page.parent){$('#workspace-page-back').textContent='← '+workspaceTitle(page.parent);$('#workspace-page-back').dataset.workspaceDestination=page.parent;}
 const related=(page.related||[]).filter(id=>workspaceDestination(id));
 $('#workspace-page-links').innerHTML=related.map(workspaceLink).join('');
 $('#workspace-related').hidden=!related.length;
 $('#api-device-control>span').textContent=state.view==='system'?'FortiGate · API durumu':'FortiGate';
 document.title=workspaceTitle(state.view)+' · FLS';
 document.querySelectorAll('#navigation [data-view]').forEach(button=>{
  const active=button.dataset.view===(page.parent||state.view);button.classList.toggle('active',active);
  if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
  button.title=workspaceTitle(button.dataset.view)+' · '+(workspacePages[button.dataset.view]?.description||'');
 });
}
function workspaceMenuRender(){
 const terms=workspaceNormalize($('#workspace-menu-search').value).split(/\s+/).filter(Boolean);
 const ids=workspaceDestinations().filter(id=>{const item=workspaceDestination(id),text=workspaceNormalize(workspaceTitle(id)+' '+item.description+' '+(item.keywords||''));return terms.every(term=>text.includes(term));});
 $('#workspace-menu-results').innerHTML=ids.length?ids.map(id=>`<button type="button" class="workspace-menu-result" data-workspace-destination="${id}"><strong>${esc(workspaceTitle(id))}</strong><span>${esc(workspaceDestination(id).description)}</span><small>${workspaceActions[id]?'Ayarlar':'Sayfa'} <span aria-hidden="true">→</span></small></button>`).join(''):'<div class="workspace-menu-empty"><strong>Eşleşen menü bulunamadı.</strong><p>Daha kısa bir sözcük deneyin: cihaz, anahtar, VPN veya arşiv.</p></div>';
 $('#workspace-menu-count').textContent=ids.length+' sonuç';
}
function workspaceMenuOpen(){
 const dialog=$('#workspace-menu-dialog');if(dialog.open||document.querySelector('dialog[open]'))return;
 workspaceMenuReturn=$('.sidebar').classList.contains('mobile-open')?$('#mobile-menu'):document.activeElement;uiMobileNavigation(false);$('#workspace-menu-search').value='';workspaceMenuRender();dialog.showModal();$('#workspace-menu-search').focus();
}
function workspaceLoadStart(){
 clearTimeout(workspaceLoadingTimer);$('#workspace-load-status').textContent='';
 document.querySelectorAll('section.view').forEach(view=>view.setAttribute('aria-busy',String(view.id==='view-'+state.view)));
 workspaceLoadingTimer=setTimeout(()=>{$('#workspace-load-status').textContent='Veriler güncelleniyor…';},500);
 uiWorkspaceEnhance();
}
function workspaceLoadFinish(){clearTimeout(workspaceLoadingTimer);$('#workspace-load-status').textContent='';$('#view-'+state.view)?.setAttribute('aria-busy','false');uiWorkspaceEnhance();}
function workspaceLoadError(error){
 const banner=$('#error-banner'),copy=document.createElement('span'),retry=document.createElement('button');
 copy.textContent=error.message;retry.type='button';retry.id='workspace-error-retry';retry.className='button';retry.textContent='Tekrar dene';retry.onclick=()=>{if(!refreshBusy)load();};
 banner.replaceChildren(copy,retry);banner.classList.remove('hidden');
}
function bindWorkspaceUx(){
 document.querySelectorAll('#workspace-menu-open,[data-workspace-menu-open]').forEach(button=>button.onclick=workspaceMenuOpen);
 $('#workspace-menu-close').onclick=()=>$('#workspace-menu-dialog').close();
 $('#workspace-menu-dialog').addEventListener('close',()=>{if(workspaceMenuReturn?.isConnected)workspaceMenuReturn.focus();});
 $('#workspace-menu-search').oninput=workspaceMenuRender;
 document.addEventListener('click',event=>{const button=event.target.closest('[data-workspace-destination]');if(button){event.preventDefault();workspaceNavigate(button.dataset.workspaceDestination);}});
 $('#workspace-menu-dialog').addEventListener('keydown',event=>{
  if(event.key==='Escape'){event.preventDefault();$('#workspace-menu-dialog').close();return;}
  const buttons=[...$('#workspace-menu-results').querySelectorAll('button')],index=buttons.indexOf(document.activeElement);
  if(['ArrowDown','ArrowUp'].includes(event.key)&&buttons.length){event.preventDefault();const next=index<0?(event.key==='ArrowDown'?0:buttons.length-1):(index+(event.key==='ArrowDown'?1:buttons.length-1))%buttons.length;buttons[next].focus();}
  if(event.key==='Enter'&&event.target===$('#workspace-menu-search')&&buttons.length){event.preventDefault();buttons[0].click();}
 });
 document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'&&!document.querySelector('dialog[open]')){event.preventDefault();workspaceMenuOpen();}});
}
