'use strict';
let archiveTlsViews=[],archiveTlsViewsLoaded=false,archiveTlsViewsLoading=false,archiveTlsViewsBusy=false,archiveTlsViewsLoadedAt=0,archiveTlsViewsError='',archiveTlsViewsNotice='',archiveTlsViewsConflict=false;
const archiveTlsViewsDraft={open:false,id:'',name:'',revision:0,confirmDelete:false};
function archiveTlsViewsConfig(){return {target:Number(archiveTlsHistoryFilters.target),status:archiveTlsHistoryFilters.status,severity:archiveTlsHistoryFilters.severity,from:archiveTlsHistoryFilters.from,to:archiveTlsHistoryFilters.to};}
function archiveTlsViewsSignature(c){return JSON.stringify([c.target,c.status,c.severity,c.from,c.to]);}
function archiveTlsViewsPanel(){
 const blocked=archiveTlsViewsBusy||archiveTlsHistoryLoading||archiveTlsHistoryExporting,pending=Boolean(archiveTlsHistoryDateDraft),active=archiveTlsViewsSignature(archiveTlsViewsConfig());
 const options=archiveTlsViews.map(v=>`<option value="${v.id}" ${String(v.id)===archiveTlsViewsDraft.id?'selected':''}>${esc(v.name)}</option>`).join('');
 const chips=archiveTlsViews.map(v=>`<button type="button" class="ftps-saved-chip" data-ftps-view-open="${v.id}" aria-pressed="${archiveTlsViewsSignature(v.configuration)===active&&!pending}" ${blocked||pending||!v.target_available?'disabled':''} title="${esc(v.target_available?'İncelemeyi aç':'Hedef artık bulunamıyor; kaydı düzenleyebilirsiniz')}">${esc(v.name)}${v.target_available?'':' · Hedef yok'}</button>`).join('');
 const status=archiveTlsViewsError||archiveTlsViewsNotice||(archiveTlsViewsLoading?'İncelemeler yükleniyor…':!archiveTlsViewsLoaded?'':pending?'Geçiş veya kayıt için önce tarih aralığını uygulayın.':archiveTlsViews.length?archiveTlsViews.length+' / 20 inceleme · Bu hesaba özel':'Uygulanan filtreleri isim vererek hesabınıza kaydedin.');
 return `<div class="ftps-saved-heading"><strong>Kayıtlı incelemeler</strong><button type="button" class="text-button" data-ftps-views-reload ${blocked||archiveTlsViewsLoading?'disabled':''}>${archiveTlsViewsConflict?'Güncel kaydı yükle':'Listeyi yenile'}</button></div><div class="ftps-saved-chips">${chips}</div><p class="ftps-saved-status ${archiveTlsViewsError?'is-error':''}" role="status">${esc(status)}</p><details id="ftps-view-editor" ${archiveTlsViewsDraft.open?'open':''}><summary>Kaydet / düzenle</summary><form id="ftps-view-form"><label>Kayıt<select id="ftps-view-choice" ${blocked?'disabled':''}><option value="">Yeni inceleme</option>${options}</select></label><label>İnceleme adı<input id="ftps-view-name" required maxlength="80" value="${esc(archiveTlsViewsDraft.name)}" placeholder="Örn. Kritik depolama uyarıları" autocomplete="off" ${blocked?'disabled':''}></label><div class="ftps-view-actions"><button type="submit" class="button" id="ftps-view-save" ${blocked||pending||!archiveTlsViewsLoaded||archiveTlsViewsConflict||!archiveTlsViewsDraft.id&&archiveTlsViews.length>=20?'disabled':''}>${archiveTlsViewsBusy?'İşleniyor…':archiveTlsViewsDraft.id?'Kaydı güncelle':'Yeni inceleme kaydet'}</button><button type="button" class="text-button" id="ftps-view-delete" ${!archiveTlsViewsDraft.id?'hidden':''} ${blocked||archiveTlsViewsConflict?'disabled':''}>Sil</button></div><p class="ftps-view-help">Hedef, açık/kapalı durumu, uygulanan tarih aralığı ve seviye birlikte kaydedilir. Güncelleme, bu kaydın filtrelerini şu anki incelemeyle değiştirir. Tarihler sabit günler olarak saklanır.</p><div id="ftps-view-delete-confirm" ${archiveTlsViewsDraft.confirmDelete?'':'hidden'}><span>Bu kayıtlı inceleme silinsin mi?</span><button type="button" class="button" id="ftps-view-confirm-delete" ${blocked?'disabled':''}>İncelemeyi sil</button><button type="button" class="text-button" id="ftps-view-cancel-delete" ${blocked?'disabled':''}>Vazgeç</button></div></form></details>`;
}
function archiveTlsViewsRender(){const root=$('#ftps-saved-views');if(root){const focused=document.activeElement?.id;root.innerHTML=archiveTlsViewsPanel();bindArchiveTlsViews();if(['ftps-view-name','ftps-view-choice'].includes(focused))root.querySelector('#'+focused)?.focus({preventScroll:true});}}
async function archiveTlsViewsLoad(resetDraft=false){
 if(archiveTlsViewsLoading||archiveTlsViewsBusy)return;archiveTlsViewsLoading=true;archiveTlsViewsError='';archiveTlsViewsRender();
 try{
  const data=await api('archive_tls_views');archiveTlsViews=data.views;archiveTlsViewsLoaded=true;archiveTlsViewsLoadedAt=Date.now();
  if(resetDraft){const v=archiveTlsViews.find(v=>String(v.id)===archiveTlsViewsDraft.id);Object.assign(archiveTlsViewsDraft,{id:v?String(v.id):'',name:v?v.name:archiveTlsViewsDraft.name,revision:v?.revision||0,confirmDelete:false});archiveTlsViewsConflict=false;}
  else if(archiveTlsViewsDraft.id){const v=archiveTlsViews.find(v=>String(v.id)===archiveTlsViewsDraft.id);if(!v||v.revision!==archiveTlsViewsDraft.revision){archiveTlsViewsConflict=true;archiveTlsViewsError='Bu inceleme başka bir oturumda değişti. Güncel kaydı yükleyin.';}}
 }catch(e){archiveTlsViewsError=e.message;}
 finally{archiveTlsViewsLoading=false;archiveTlsViewsRender();}
}
async function archiveTlsViewsOpen(id){
 if(archiveTlsViewsBusy||archiveTlsHistoryLoading||archiveTlsHistoryExporting||archiveTlsHistoryDateDraft)return;
 archiveTlsViewsBusy=true;archiveTlsViewsError='';archiveTlsViewsNotice='';archiveTlsHistoryRender();
 try{
  const data=await api('archive_tls_view',false,{tls_view_id:String(id)}),view=data.view,c=view.configuration;
  archiveTlsViews=archiveTlsViews.map(v=>v.id===view.id?{...view,target_available:true}:v);
  Object.assign(archiveTlsHistoryFilters,{...c,target:String(c.target),page:1});archiveTlsHistoryDateDraft=null;archiveTlsHistoryResetSelection();archiveTlsHistorySyncUrl();archiveTlsViewsNotice=view.name+' açıldı.';
  archiveTlsViewsBusy=false;await archiveTlsHistoryLoad();
 }catch(e){archiveTlsViewsError=e.message;}
 finally{archiveTlsViewsBusy=false;archiveTlsHistoryRender();$('#ftps-saved-views [data-ftps-view-open="'+id+'"]')?.focus({preventScroll:true});}
}
async function archiveTlsViewsWrite(remove=false){
 if(archiveTlsViewsBusy||archiveTlsHistoryLoading||archiveTlsHistoryExporting||archiveTlsViewsConflict||!remove&&archiveTlsHistoryDateDraft)return;
 const form=$('#ftps-view-form');if(!remove&&!form?.reportValidity())return;
 const body=new FormData();if(archiveTlsViewsDraft.id){body.set('id',archiveTlsViewsDraft.id);body.set('revision',String(archiveTlsViewsDraft.revision));}
 if(!remove){body.set('name',archiveTlsViewsDraft.name.trim());body.set('configuration',JSON.stringify(archiveTlsViewsConfig()));}
 archiveTlsViewsBusy=true;archiveTlsViewsError='';archiveTlsViewsNotice='';archiveTlsHistoryRender();
 try{
  const response=await fetch('/api.php?route='+(remove?'delete_archive_tls_view':'save_archive_tls_view'),{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
  if(response.status===401){location.href='/';return;}
  const data=await response.json();if(!response.ok){if(data.code==='tls_view_conflict')archiveTlsViewsConflict=true;throw new Error(data.error||'İnceleme kaydedilemedi.');}
  archiveTlsViews=data.views;archiveTlsViewsLoaded=true;archiveTlsViewsLoadedAt=Date.now();archiveTlsViewsConflict=false;
  Object.assign(archiveTlsViewsDraft,remove?{id:'',name:'',revision:0,confirmDelete:false}:{id:String(data.view.id),name:data.view.name,revision:data.view.revision,confirmDelete:false});
  archiveTlsViewsNotice=remove?'Kayıtlı inceleme silindi.':data.changed?'İnceleme hesabınıza kaydedildi.':'İnceleme zaten güncel.';
 }catch(e){archiveTlsViewsError=e instanceof TypeError?'Kaydedilemedi. Ad ve filtreler korunuyor; yeniden deneyin.':e.message;}
 finally{archiveTlsViewsBusy=false;archiveTlsHistoryRender();$('#ftps-view-save')?.focus({preventScroll:true});}
}
function bindArchiveTlsViews(){
 const root=$('#ftps-saved-views');if(!root)return;
 root.querySelectorAll('[data-ftps-view-open]').forEach(b=>b.onclick=()=>archiveTlsViewsOpen(Number(b.dataset.ftpsViewOpen)));
 root.querySelectorAll('[data-ftps-views-reload]').forEach(b=>b.onclick=()=>archiveTlsViewsLoad(archiveTlsViewsConflict));
 const editor=root.querySelector('#ftps-view-editor');if(editor)editor.ontoggle=()=>{archiveTlsViewsDraft.open=editor.open;};
 const choice=root.querySelector('#ftps-view-choice');if(choice)choice.onchange=()=>{const v=archiveTlsViews.find(v=>String(v.id)===choice.value);Object.assign(archiveTlsViewsDraft,{id:v?String(v.id):'',name:v?.name||'',revision:v?.revision||0,confirmDelete:false});archiveTlsViewsConflict=false;archiveTlsViewsError='';archiveTlsViewsNotice='';archiveTlsViewsRender();};
 const name=root.querySelector('#ftps-view-name');if(name)name.oninput=()=>{archiveTlsViewsDraft.name=name.value;};
 const form=root.querySelector('#ftps-view-form');if(form)form.onsubmit=e=>{e.preventDefault();archiveTlsViewsWrite();};
 const remove=root.querySelector('#ftps-view-delete');if(remove)remove.onclick=()=>{archiveTlsViewsDraft.confirmDelete=true;archiveTlsViewsRender();$('#ftps-view-confirm-delete')?.focus();};
 const confirm=root.querySelector('#ftps-view-confirm-delete');if(confirm)confirm.onclick=()=>archiveTlsViewsWrite(true);
 const cancel=root.querySelector('#ftps-view-cancel-delete');if(cancel)cancel.onclick=()=>{archiveTlsViewsDraft.confirmDelete=false;archiveTlsViewsRender();};
 // Fetch on entry and at most once per 30 seconds while the history is open.
 if(archiveTlsHistoryOpen&&!archiveTlsViewsLoading&&!archiveTlsViewsBusy&&!archiveTlsViewsError&&(!archiveTlsViewsLoaded||Date.now()-archiveTlsViewsLoadedAt>=30000))archiveTlsViewsLoad();
}
