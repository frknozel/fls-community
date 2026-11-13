'use strict';
const savedEventViewFilterKeys=['target_key','target_label','source_reason','source_reason_label','outcome','policy','profile','module','source','reason','block_reason','block_reason_label','profile_missing','source_missing','policy_scope','q_field','q'];
let savedEventViews=[],savedEventViewsLoaded=false,savedEventViewsBusy=false,savedEventViewsError='',savedEventViewsConflict=false,savedEventViewsUnconfirmed=false,savedEventViewSelected=null,savedEventViewsMarkup='',savedEventDefaultRequested=false,savedEventViewsOrderToken='',savedEventViewsOrderDraft=null,savedEventViewsOrderConflict=false,savedEventViewsOrderError='',savedEventViewsReordering=false,savedEventViewDragged=null,savedEventViewClickUntil=0,savedEventViewsOrderSaving=false;
const savedEventViewWriteKey='fls-unconfirmed-view-write:'+String(document.documentElement.dataset.userId||'');
let savedEventViewWriteInFlight=false;
function savedEventViewWritePending(value){
 savedEventViewsUnconfirmed=value;
 try{if(value)sessionStorage.setItem(savedEventViewWriteKey,'1');else sessionStorage.removeItem(savedEventViewWriteKey);}catch{}
 if(value){savedEventViewsConflict=true;eventColumnsConflict=true;savedEventViewsError='İsteğin sonucu doğrulanamadı. İşlem otomatik tekrarlanmadı; güncel görünüm ve sütun tercihlerini yükleyin.';eventColumnsError=savedEventViewsError;}
}
function restoreSavedEventViewWrite(){try{if(sessionStorage.getItem(savedEventViewWriteKey)==='1')savedEventViewWritePending(true);}catch{}}
restoreSavedEventViewWrite();
function savedEventLayoutValid(value){
 const keys=eventColumnKeys,object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value),subset=values=>Array.isArray(values)&&values.every(key=>keys.includes(key))&&new Set(values).size===values.length;
 return object(value)&&subset(value.columns)&&value.columns.length>0&&subset(value.order)&&value.order.length===keys.length&&subset(value.pinned)&&object(value.widths)&&Object.entries(value.widths).every(([key,width])=>keys.includes(key)&&Number.isInteger(width)&&width>=80&&width<=1200);
}
function savedEventPreferencesValid(value){return savedEventLayoutValid(value)&&Number.isSafeInteger(value.revision)&&value.revision>=0;}
function savedEventConfigurationValid(config){
 if(!config||typeof config!=='object'||Array.isArray(config)||config.version!==1||!['today','hour','24h','7d','fast','all','custom'].includes(config.period)||typeof config.from!=='string'||typeof config.to!=='string'||!['group_av','group_security','group_traffic'].every(key=>typeof config[key]==='boolean')||!savedEventLayoutValid(config.layout))return false;
 const filters=config.filters;if(!filters||typeof filters!=='object'||Array.isArray(filters)||Object.keys(filters).some(key=>!savedEventViewFilterKeys.includes(key))||!savedEventViewFilterKeys.every(key=>key==='q_field'&&!Object.hasOwn(filters,key)||typeof filters[key]==='string'&&filters[key].length<=4096))return false;
 return config.period==='custom'?Number.isFinite(Date.parse(config.from))&&(config.to===''||Number.isFinite(Date.parse(config.to))):config.from===''&&config.to==='';
}
function savedEventViewValid(view){
 return view!==null&&typeof view==='object'&&!Array.isArray(view)&&Number.isSafeInteger(view.id)&&view.id>0&&Number.isSafeInteger(view.revision)&&view.revision>0&&typeof view.name==='string'&&view.name.length>0&&view.name.length<=160&&typeof view.is_default==='boolean'&&savedEventConfigurationValid(view.configuration);
}
function savedEventViewsValid(data){
 return data!==null&&typeof data==='object'&&Array.isArray(data.views)&&data.views.length<=20&&data.views.every(savedEventViewValid)&&new Set(data.views.map(view=>view.id)).size===data.views.length&&data.views.filter(view=>view.is_default).length<=1&&typeof data.order_token==='string'&&/^[a-f0-9]{64}$/.test(data.order_token);
}
function savedEventLayoutSignature(value){return JSON.stringify({columns:eventColumnKeys.filter(key=>value.columns.includes(key)),order:value.order,widths:eventColumnKeys.filter(key=>Object.hasOwn(value.widths,key)).map(key=>[key,value.widths[key]]),pinned:eventColumnKeys.filter(key=>value.pinned.includes(key))});}
function savedEventViewResponseValid(route,values,data){
 if(route==='apply_event_view'){
  const expected=savedEventViews.find(view=>view.id===Number(values.id)&&view.revision===Number(values.revision));
  return Boolean(expected)&&savedEventViewValid(data.view)&&data.view.id===expected.id&&data.view.revision===expected.revision&&savedEventViewSignature(expected.configuration)===savedEventViewSignature(data.view.configuration)&&savedEventPreferencesValid(data.preferences)&&data.preferences.revision>=Number(values.columns_revision)&&savedEventLayoutSignature(data.view.configuration.layout)===savedEventLayoutSignature(data.preferences);
 }
 if(!savedEventViewsValid(data)||typeof data.changed!=='boolean')return false;
 if(route==='delete_event_view')return data.view===null&&!data.views.some(view=>view.id===Number(values.id));
 if(route==='set_default_event_view')return Number(values.id)===0?!data.views.some(view=>view.is_default):data.views.some(view=>view.id===Number(values.id)&&view.is_default);
 if(route==='reorder_event_views'){try{const ids=JSON.parse(values.order);return Array.isArray(ids)&&JSON.stringify(data.views.map(view=>view.id))===JSON.stringify(ids.map(Number));}catch{return false;}}
 if(route==='save_event_view'){
  try{return savedEventViewValid(data.view)&&(!values.id||data.view.id===Number(values.id))&&data.view.name===values.name&&savedEventConfigurationValid(JSON.parse(values.configuration))&&savedEventViewSignature(data.view.configuration)===savedEventViewSignature(JSON.parse(values.configuration))&&data.views.some(view=>view.id===data.view.id&&view.revision===data.view.revision&&savedEventViewSignature(view.configuration)===savedEventViewSignature(data.view.configuration));}catch{return false;}
 }
 return false;
}
function savedEventViewCapture(){
 const layout=eventLayout();
 return {version:1,period:state.period,from:state.period==='custom'?state.from:'',to:state.period==='custom'?state.to:'',group_av:state.groupAv,group_security:state.groupSecurity,group_traffic:state.groupTraffic,filters:Object.fromEntries(savedEventViewFilterKeys.map(key=>[key,state.filters[key]||''])),layout:{columns:[...eventColumnsModel.columns],order:[...layout.order],widths:{...layout.widths},pinned:[...layout.pinned]}};
}
function savedEventViewSignature(config){
 const date=value=>{if(!value)return '';const offset=/(Z|[+-]\d\d:\d\d)$/.test(value)?value:value+'+03:00',fraction=(value.match(/\.(\d{1,6})(?:Z|[+-]\d\d:\d\d)?$/)?.[1]||'').padEnd(6,'0');return new Date(offset).toISOString().replace(/\.\d{3}Z$/,'.'+fraction+'Z');};
 try{return JSON.stringify({...config,from:date(config.from),to:date(config.to),filters:Object.fromEntries(savedEventViewFilterKeys.map(key=>[key,config.filters[key]||''])),layout:{columns:eventColumnKeys.filter(key=>config.layout.columns.includes(key)),order:config.layout.order,widths:Object.fromEntries(eventColumnKeys.filter(key=>Object.hasOwn(config.layout.widths,key)).map(key=>[key,config.layout.widths[key]])),pinned:eventColumnKeys.filter(key=>config.layout.pinned.includes(key))}});}catch{return '';}
}
function savedEventViewsRender(){
 const root=$('#saved-event-views-list');if(!root||savedEventViewsReordering)return;
 const locked=savedEventViewsUnconfirmed||savedEventViewsBusy||eventColumnsSaving||eventColumnsEditing||!eventColumnsModel||eventColumnsConflict,current=eventColumnsModel?savedEventViewSignature(savedEventViewCapture()):'',matches=savedEventViews.filter(view=>savedEventViewSignature(view.configuration)===current),active=matches.find(view=>view.id===savedEventViewSelected)||matches[0];
 const canReorder=!locked&&!savedEventViewsOrderConflict&&savedEventViews.length>1,markup=savedEventViewsDisplay().map(view=>`<button type="button" class="saved-view-chip" draggable="${canReorder}" aria-keyshortcuts="Alt+ArrowLeft Alt+ArrowRight Alt+Home Alt+End" data-saved-view="${view.id}" aria-pressed="${view.id===active?.id}" ${locked?'disabled':''} title="${esc(view.name)} · Açmak için tıklayın; sıralamak için sürükleyin veya Alt + ok tuşlarını kullanın."><span class="saved-view-order-grip" aria-hidden="true"></span>${view.is_default?'<span class="saved-view-default-mark" aria-label="Varsayılan">★</span>':''}${esc(view.name)}</button>`).join('');
 if(markup!==savedEventViewsMarkup){const left=root.scrollLeft;root.innerHTML=markup;root.scrollLeft=left;savedEventViewsMarkup=markup;root.querySelectorAll('[data-saved-view]').forEach(button=>bindSavedEventViewOrder(button,canReorder));}
 $('#saved-view-open').disabled=locked||!savedEventViewsLoaded||Boolean(savedEventViewsOrderDraft)||savedEventViewsOrderConflict;
 const defaultView=savedEventViews.find(view=>view.is_default),defaultButton=$('#saved-view-default-open');if(defaultButton){defaultButton.textContent=defaultView?'★ Varsayılan: '+defaultView.name:'Varsayılan seç';defaultButton.disabled=locked||!savedEventViewsLoaded||!savedEventViews.length||Boolean(savedEventViewsOrderDraft)||savedEventViewsOrderConflict;defaultButton.title='Engeller ve kayıtlar açılış görünümünü seçin';}
 $('#saved-views-status').textContent=savedEventViewsOrderSaving?'Sıra kaydediliyor…':savedEventViewsBusy?'Görünüm işleniyor…':savedEventViewsOrderError||savedEventViewsError||(savedEventViewsOrderDraft?'Sıra henüz kaydedilmedi.':null)||(!savedEventViewsLoaded?'Görünümler yükleniyor…':!savedEventViews.length?'Seçili FortiGate için filtre ve sütun düzenini isim vererek kaydedin.':active?'Etkin görünüm: '+active.name:'Özel inceleme · kaydedilmiş görünümlerden farklı');
 $('#saved-views-status').classList.toggle('saved-view-error',Boolean(savedEventViewsError||savedEventViewsOrderError));$('#saved-views-reload').hidden=!savedEventViewsError&&!savedEventViewsOrderError;$('#saved-views-reload').disabled=savedEventViewsBusy;
 const dialog=$('#saved-view-dialog');if(dialog?.open){$('#saved-view-submit').disabled=savedEventViewsBusy||savedEventViewsConflict||Boolean(savedEventViewsOrderDraft)||savedEventViewsOrderConflict;$('#saved-view-delete').disabled=savedEventViewsBusy||savedEventViewsConflict||Boolean(savedEventViewsOrderDraft)||savedEventViewsOrderConflict;$('#saved-view-name').disabled=savedEventViewsBusy;$('#saved-view-choice').disabled=savedEventViewsBusy;$('#saved-view-close').disabled=savedEventViewsBusy;$('#saved-view-confirm-delete').disabled=savedEventViewsBusy||savedEventViewsUnconfirmed;$('#saved-view-cancel-delete').disabled=savedEventViewsBusy;$('#saved-view-form-reload').disabled=savedEventViewsBusy;if($('#saved-view-set-default'))$('#saved-view-set-default').disabled=savedEventViewsBusy||savedEventViewsConflict||Boolean(savedEventViewsOrderDraft)||savedEventViewsOrderConflict;}
 savedEventViewsOrderControls();
}
function savedEventViewsDialogOptions(reset=false){
 const select=$('#saved-view-choice'),chosen=reset?'':select.value;
 select.replaceChildren(new Option('Yeni görünüm',''),...savedEventViewsDisplay().map(view=>new Option((view.is_default?'★ ':'')+view.name,String(view.id))));select.value=savedEventViews.some(view=>String(view.id)===chosen)?chosen:'';
 if(reset)$('#saved-view-name').value='';
 savedEventViewsDialogChoice(false);
}
function savedEventViewsDialogChoice(fill=true){
 const view=savedEventViews.find(view=>String(view.id)===$('#saved-view-choice').value);
 if(fill)$('#saved-view-name').value=view?.name||'';
 $('#saved-view-submit').textContent=view?'Görünümü güncelle':'Yeni görünüm kaydet';$('#saved-view-delete').hidden=!view;$('#saved-view-delete-confirmation').hidden=true;
 if($('#saved-view-default-section')){$('#saved-view-default-section').hidden=!view;$('#saved-view-set-default').textContent=view?.is_default?'Varsayılanı kaldır':'Varsayılan yap';}
 $('#saved-view-current-help').textContent=view?'Güncelleme, adı ve kayıtlı ayarları şu anki incelemenin filtre ve sütun düzeniyle değiştirir.':'Uygulanmış filtreler, zaman aralığı, gruplama ve sütun düzeni birlikte saklanır.';
 $('#saved-view-form-error').textContent='';savedEventViewsOrderControls();
}
async function loadSavedEventViews(signal,force=false,discardOrder=false){
 if(savedEventViewsUnconfirmed)return false;
 if(savedEventViewsLoaded&&!force)return true;
 try{const data=await api('event_views',false,{},signal);if(signal?.aborted)return;if(!savedEventViewsValid(data))throw new Error('Görünüm listesi okunamadı.');if(savedEventViewsOrderDraft&&!discardOrder){if(data.order_token!==savedEventViewsOrderToken){savedEventViewsOrderConflict=true;savedEventViewsOrderError='Görünüm listesi başka bir oturumda değişti. Güncel listeyi yükleyip yeniden sıralayın.';savedEventViewsRender();return false;}}else acceptSavedEventViews(data,true);savedEventViewsLoaded=true;savedEventViewsError='';savedEventViewsConflict=false;if($('#saved-view-dialog').open)savedEventViewsDialogOptions();savedEventViewsRender();return true;}
 catch(error){if(error.name==='AbortError')return;savedEventViewsError='Görünümler yüklenemedi. Güncel listeyi yeniden yükleyin.';}
 savedEventViewsRender();return false;
}
async function savedEventViewRequest(route,values,signal){
 if(savedEventViewsUnconfirmed)throw new Error('Önceki isteğin sonucu doğrulanamadı. Yeni işlemden önce güncel görünüm ve sütun tercihlerini yükleyin.');
 if(savedEventViewWriteInFlight)throw new Error('Önceki görünüm isteği sürüyor. Sonucunu bekleyin.');
 const body=new FormData();for(const[key,value]of Object.entries(values))body.set(key,String(value));
 // Record the pending write before dispatch so reload cannot replay an
 // unfinished default-view request before its response is known.
 try{sessionStorage.setItem(savedEventViewWriteKey,'1');}catch{}
 savedEventViewWriteInFlight=true;
 try{const data=await apiWrite(route,body,signal,data=>savedEventViewResponseValid(route,values,data));savedEventViewWritePending(false);return data;}
 catch(error){
  savedEventViewWritePending(Boolean(error.ambiguous));
  throw error;
 }finally{savedEventViewWriteInFlight=false;}
}
async function reloadSavedEventViewState(){
 if(savedEventViewsBusy||eventColumnsSaving||savedEventViewWriteInFlight)return;
 savedEventViewsBusy=true;eventColumnsSaving=true;eventColumnsControls();savedEventViewsRender();
 try{
  const [views,preferences]=await Promise.all([api('event_views'),api('event_columns')]);
  if(!savedEventViewsValid(views)||!savedEventPreferencesValid(preferences))throw new Error('Güncel görünüm ve sütun tercihleri doğrulanamadı.');
  acceptSavedEventViews(views,true);eventAcceptColumns(preferences);eventColumnsDraft=null;eventLayoutDraft=null;eventColumnsConflict=false;eventColumnsError='';
  savedEventViewWritePending(false);savedEventViewsConflict=false;savedEventViewsLoaded=true;savedEventViewsError='';applyEventColumns();
  if($('#saved-view-dialog').open)savedEventViewsDialogOptions();
 }catch(error){savedEventViewsError='Güncel görünüm ve sütun tercihleri yüklenemedi. Yeniden yükleyin.';}
 finally{savedEventViewsBusy=false;eventColumnsSaving=false;eventColumnsControls();savedEventViewsRender();}
}
function commitSavedEventView(data,mode){
 if(!savedEventViewValid(data.view)||!savedEventPreferencesValid(data.preferences)||savedEventLayoutSignature(data.view.configuration.layout)!==savedEventLayoutSignature(data.preferences))throw new Error('Görünüm yanıtı doğrulanamadı.');
 const config=data.view.configuration;
  // Commit the filters only after the complete column preference has been saved successfully.
  eventAcceptColumns(data.preferences);eventColumnsDraft=null;eventLayoutDraft=null;eventColumnsError='';eventColumnsConflict=false;
  state.period=config.period;state.from=config.from;state.to=config.to;state.filters={...config.filters};state.groupAv=config.group_av;state.groupSecurity=config.group_security;state.groupTraffic=config.group_traffic;state.page=1;
  $('#period').value=state.period;uiDateInputs();$('#custom-range').classList.toggle('hidden',state.period!=='custom');
  for(const[key,field]of [['av','groupAv'],['security','groupSecurity'],['traffic','groupTraffic']])$('#group-'+key).checked=state[field];
  for(const key of ['module','policy','profile']){const select=$('#filter-'+key),value=state.filters[key];if(value&&![...select.options].some(option=>option.value===value))select.add(new Option(moduleNames[value]||value,value));}
  savedEventViewSelected=data.view.id;syncFilters();applyEventColumns();syncUrl(mode);const table=$('#events-table');table.scrollTop=0;table.scrollLeft=0;
}
async function applySavedEventView(id){
 const device=String(state.fgDevice),origin=state.view,current=()=>device===String(state.fgDevice)&&origin===state.view;
 const view=savedEventViews.find(view=>view.id===id);if(!view||savedEventViewsBusy||eventColumnsSaving||eventColumnsEditing||eventColumnsConflict||!eventColumnsModel)return;
 savedEventViewsBusy=true;eventColumnsSaving=true;savedEventViewsError='';eventColumnsControls();savedEventViewsRender();
 try{
  const data=await savedEventViewRequest('apply_event_view',{id:view.id,revision:view.revision,columns_revision:eventColumnsModel.revision}),config=data.view.configuration;
  if(!current()){eventAcceptColumns(data.preferences);eventColumnsDraft=null;eventLayoutDraft=null;return;}
  commitSavedEventView(data,'push');await load();
  toast(data.view.name+' görünümü açıldı.');
 }catch(error){
  if(!current())return;
  if(error.data?.code==='column_conflict'){if(savedEventPreferencesValid(error.data))eventAcceptColumns(error.data);eventColumnsConflict=true;eventColumnsError=error.message;}
  savedEventViewsError=error instanceof TypeError?'Görünüm açılamadı. Mevcut filtre ve sütun düzeniniz korunuyor.':error.message;
 }finally{savedEventViewsBusy=false;eventColumnsSaving=false;eventColumnsControls();savedEventViewsRender();if(current())$('#saved-event-views-list [data-saved-view="'+id+'"]')?.focus({preventScroll:true});}
}
async function saveNamedEventView(remove=false){
 if(savedEventViewsBusy||eventColumnsSaving||!eventColumnsModel||savedEventViewsConflict||savedEventViewsOrderDraft||savedEventViewsOrderConflict)return;
 const form=$('#saved-view-form');if(!remove&&!form.reportValidity())return;
 const view=savedEventViews.find(view=>String(view.id)===$('#saved-view-choice').value),values=remove?{}:{name:$('#saved-view-name').value.trim(),configuration:JSON.stringify(savedEventViewCapture())};
 if(view){values.id=view.id;values.revision=view.revision;}if(remove&&!view)return;
 savedEventViewsBusy=true;savedEventViewsError='';$('#saved-view-form-error').textContent='';savedEventViewsRender();
 try{const data=await savedEventViewRequest(remove?'delete_event_view':'save_event_view',values);acceptSavedEventViews(data,true);savedEventViewsLoaded=true;savedEventViewSelected=remove?null:data.view.id;$('#saved-view-dialog').close();toast(remove?'Kayıtlı görünüm silindi.':'Görünüm hesabınıza kaydedildi.');}
 catch(error){savedEventViewsConflict=savedEventViewsUnconfirmed||error.data?.code==='view_conflict'||error.data?.code==='not_found';$('#saved-view-form-error').textContent=error instanceof TypeError?'Kaydedilemedi. Ad ve mevcut incelemeniz korunuyor; yeniden deneyin.':error.message;if(savedEventViewsConflict)savedEventViewsError=error.message;}
 finally{savedEventViewsBusy=false;savedEventViewsRender();}
}
function bindSavedEventViews(){
 const dialog=$('#saved-view-dialog');$('#saved-view-open').onclick=()=>{savedEventViewsConflict=false;savedEventViewsDialogOptions(true);dialog.showModal();savedEventViewsRender();$('#saved-view-name').focus();};
 $('#saved-view-choice').onchange=()=>savedEventViewsDialogChoice();$('#saved-view-form').onsubmit=event=>{event.preventDefault();saveNamedEventView();};$('#saved-view-close').onclick=()=>dialog.close();
 dialog.addEventListener('cancel',event=>{if(savedEventViewsBusy)event.preventDefault();});dialog.addEventListener('close',()=>$('#saved-view-open').focus({preventScroll:true}));
 $('#saved-view-delete').onclick=()=>{$('#saved-view-delete-confirmation').hidden=false;$('#saved-view-confirm-delete').focus();};$('#saved-view-cancel-delete').onclick=()=>{$('#saved-view-delete-confirmation').hidden=true;$('#saved-view-delete').focus();};$('#saved-view-confirm-delete').onclick=()=>saveNamedEventView(true);
 if($('#saved-view-set-default'))$('#saved-view-set-default').onclick=setSavedEventDefault;if($('#saved-view-default-open'))$('#saved-view-default-open').onclick=()=>{const view=savedEventViews.find(view=>view.is_default)||savedEventViews.find(view=>view.id===savedEventViewSelected)||savedEventViews[0];$('#saved-view-open').click();if(view){$('#saved-view-choice').value=String(view.id);savedEventViewsDialogChoice();}};
 $('#saved-views-reload').onclick=reloadSavedEventViewState;$('#saved-view-form-reload').onclick=reloadSavedEventViewState;bindSavedEventViewsOrder();savedEventViewsRender();
}

function savedEventDefaultEligible(search){
 const query=new URLSearchParams(search);
 return ![...savedEventViewFilterKeys,'period','from','to','page','group_av','group_security','group_traffic'].some(key=>query.has(key));
}
function requestSavedEventDefault(requested){savedEventDefaultRequested=Boolean(requested);}
function consumeSavedEventDefault(){const requested=savedEventDefaultRequested;savedEventDefaultRequested=false;return requested;}
function hasSavedEventDefault(){return savedEventViews.some(view=>view.is_default);}
async function applySavedEventDefault(signal){
 const view=savedEventViews.find(view=>view.is_default);if(!view||signal.aborted||!eventColumnsModel||savedEventViewsUnconfirmed||savedEventViewsBusy||eventColumnsSaving)return;
 savedEventViewsBusy=true;eventColumnsSaving=true;savedEventViewsError='';eventColumnsControls();
 try{
  const data=await savedEventViewRequest('apply_event_view',{id:view.id,revision:view.revision,columns_revision:eventColumnsModel.revision},signal);if(signal.aborted)return;
  commitSavedEventView(data,'replace');
 }catch(error){
  if(error.name==='AbortError')return;
  if(error.data?.code==='column_conflict'){if(savedEventPreferencesValid(error.data))eventAcceptColumns(error.data);eventColumnsConflict=true;eventColumnsError=error.message;}
  savedEventViewsError='Varsayılan görünüm yüklenemedi. '+(error instanceof TypeError?'Mevcut incelemeniz korunuyor; görünümü yeniden seçebilirsiniz.':error.message);
 }finally{savedEventViewsBusy=false;eventColumnsSaving=false;eventColumnsControls();savedEventViewsRender();}
}
async function setSavedEventDefault(){
 const view=savedEventViews.find(view=>String(view.id)===$('#saved-view-choice').value),previous=savedEventViews.find(view=>view.is_default);
 if(!view||savedEventViewsBusy||savedEventViewsConflict||savedEventViewsOrderDraft||savedEventViewsOrderConflict)return;
 savedEventViewsBusy=true;savedEventViewsError='';$('#saved-view-form-error').textContent='';savedEventViewsRender();
 try{
  const data=await savedEventViewRequest('set_default_event_view',{id:view.is_default?0:view.id,revision:view.is_default?0:view.revision,previous_id:previous?.id||0,previous_revision:previous?.revision||0});
  acceptSavedEventViews(data,true);savedEventViewsDialogOptions();toast(view.is_default?'Varsayılan seçimi kaldırıldı.':view.name+' varsayılan seçildi.');
 }catch(error){savedEventViewsConflict=savedEventViewsUnconfirmed||['view_conflict','default_conflict','not_found'].includes(error.data?.code);$('#saved-view-form-error').textContent=error instanceof TypeError?'Varsayılan seçimi kaydedilemedi. Önceki seçiminiz korunuyor.':error.message;if(savedEventViewsConflict)savedEventViewsError=error.message;}
 finally{savedEventViewsBusy=false;savedEventViewsRender();}
}

function savedEventViewsDisplay(){return savedEventViewsOrderDraft?savedEventViewsOrderDraft.map(id=>savedEventViews.find(view=>view.id===id)).filter(Boolean):savedEventViews;}
function acceptSavedEventViews(data,clearOrder=false){
 if(!savedEventViewsValid(data))throw new Error('Görünüm sırası okunamadı. Güncel listeyi yükleyin.');
 savedEventViews=data.views;savedEventViewsOrderToken=data.order_token;
 if(clearOrder){savedEventViewsOrderDraft=null;savedEventViewsOrderConflict=false;savedEventViewsOrderError='';}
}
function savedEventViewsOrderControls(){
 const retry=$('#saved-view-order-save');if(retry){retry.hidden=!savedEventViewsOrderDraft;retry.disabled=savedEventViewsBusy||savedEventViewsUnconfirmed||savedEventViewsOrderConflict;}
 const section=$('#saved-view-order-section');if(!section)return;
 const selected=Number($('#saved-view-choice').value),order=savedEventViewsDisplay().map(view=>view.id),index=order.indexOf(selected);section.hidden=index<0;
 $('#saved-view-position').textContent=index<0?'':(index+1)+' / '+order.length;
 $('#saved-view-move-left').disabled=savedEventViewsBusy||savedEventViewsUnconfirmed||savedEventViewsOrderConflict||index<=0;$('#saved-view-move-right').disabled=savedEventViewsBusy||savedEventViewsUnconfirmed||savedEventViewsOrderConflict||index<0||index>=order.length-1;
 $('#saved-view-order-retry').hidden=!savedEventViewsOrderDraft;$('#saved-view-order-retry').disabled=savedEventViewsBusy||savedEventViewsUnconfirmed||savedEventViewsOrderConflict;
}
function focusSavedEventView(id){
 const root=$('#saved-event-views-list'),button=root.querySelector('[data-saved-view="'+id+'"]');if(!button)return;button.focus({preventScroll:true});const a=button.getBoundingClientRect(),b=root.getBoundingClientRect();if(a.left<b.left)root.scrollLeft+=a.left-b.left;else if(a.right>b.right)root.scrollLeft+=a.right-b.right;
}
function clearSavedEventViewDrag(){
 savedEventViewsReordering=false;savedEventViewDragged=null;document.querySelectorAll('#saved-event-views-list [data-saved-view]').forEach(button=>{button.classList.remove('saved-view-dragging');delete button.dataset.dropSide;});
}
function moveSavedEventView(id,index){
 if(savedEventViewsBusy||savedEventViewsUnconfirmed||eventColumnsSaving||eventColumnsEditing||savedEventViewsOrderConflict)return;
 const order=savedEventViewsDisplay().map(view=>view.id),from=order.indexOf(id);if(from<0||index<0||index>=order.length||from===index)return;
 order.splice(from,1);order.splice(index,0,id);savedEventViewsOrderDraft=order.every((id,i)=>id===savedEventViews[i].id)?null:order;savedEventViewsOrderError='';savedEventViewsRender();focusSavedEventView(id);saveSavedEventViewOrder(id);
}
async function saveSavedEventViewOrder(focusId=null){
 if(!savedEventViewsOrderDraft||savedEventViewsBusy||savedEventViewsUnconfirmed||savedEventViewsOrderConflict)return;
 savedEventViewsBusy=true;savedEventViewsOrderSaving=true;savedEventViewsOrderError='';if($('#saved-view-dialog').open)$('#saved-view-form-error').textContent='';savedEventViewsRender();
 try{const data=await savedEventViewRequest('reorder_event_views',{order:JSON.stringify(savedEventViewsOrderDraft.map(String)),snapshot:savedEventViewsOrderToken});acceptSavedEventViews(data,true);if($('#saved-view-dialog').open)savedEventViewsDialogOptions();toast('Görünüm sırası hesabınıza kaydedildi.');}
 catch(error){savedEventViewsOrderConflict=savedEventViewsUnconfirmed||error.data?.code==='order_conflict';savedEventViewsOrderError=error instanceof TypeError?'Sıra kaydedilemedi. Yerel sıranız korunuyor; yeniden deneyin.':error.message;if($('#saved-view-dialog').open)$('#saved-view-form-error').textContent=savedEventViewsOrderError;}
 finally{savedEventViewsBusy=false;savedEventViewsOrderSaving=false;savedEventViewsRender();if(focusId!==null&&!$('#saved-view-dialog').open)focusSavedEventView(focusId);}
}
function bindSavedEventViewOrder(button,enabled){
 const id=Number(button.dataset.savedView);
 button.onclick=event=>{if(performance.now()<savedEventViewClickUntil){event.preventDefault();return;}applySavedEventView(id);};
 button.onkeydown=event=>{if(!event.altKey||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();event.stopPropagation();if(!enabled)return;const order=savedEventViewsDisplay().map(view=>view.id),index=order.indexOf(id);moveSavedEventView(id,event.key==='Home'?0:event.key==='End'?order.length-1:index+(event.key==='ArrowRight'?1:-1));};
 button.ondragstart=event=>{if(!enabled){event.preventDefault();return;}savedEventViewsReordering=true;savedEventViewDragged=id;savedEventViewClickUntil=performance.now()+300;event.dataTransfer.setData('application/x-fls-view',String(id));event.dataTransfer.effectAllowed='move';button.classList.add('saved-view-dragging');};
 button.ondragover=event=>{if(savedEventViewDragged===null||savedEventViewDragged===id)return;event.preventDefault();event.dataTransfer.dropEffect='move';document.querySelectorAll('#saved-event-views-list [data-drop-side]').forEach(node=>delete node.dataset.dropSide);const rect=button.getBoundingClientRect();button.dataset.dropSide=event.clientX>rect.left+rect.width/2?'after':'before';const root=$('#saved-event-views-list'),a=root.getBoundingClientRect();if(event.clientX>a.right-24)root.scrollLeft+=18;else if(event.clientX<a.left+24)root.scrollLeft-=18;};
 button.ondrop=event=>{if(savedEventViewDragged===null)return;event.preventDefault();event.stopPropagation();const moving=savedEventViewDragged,after=button.dataset.dropSide==='after',others=savedEventViewsDisplay().map(view=>view.id).filter(key=>key!==moving),index=others.indexOf(id)+(after?1:0);clearSavedEventViewDrag();savedEventViewClickUntil=performance.now()+300;moveSavedEventView(moving,index);};
 button.ondragend=()=>{savedEventViewClickUntil=performance.now()+300;clearSavedEventViewDrag();};
}
function bindSavedEventViewsOrder(){
 if($('#saved-view-order-save'))$('#saved-view-order-save').onclick=()=>saveSavedEventViewOrder();
 for(const[selector,delta]of [['#saved-view-move-left',-1],['#saved-view-move-right',1]])if($(selector))$(selector).onclick=()=>{const id=Number($('#saved-view-choice').value),order=savedEventViewsDisplay().map(view=>view.id);moveSavedEventView(id,order.indexOf(id)+delta);};
 if($('#saved-view-order-retry'))$('#saved-view-order-retry').onclick=()=>saveSavedEventViewOrder();
 document.addEventListener('keydown',event=>{if(event.key==='Escape'&&savedEventViewsReordering)clearSavedEventViewDrag();});
 document.addEventListener('visibilitychange',()=>{if(document.hidden&&savedEventViewsReordering)clearSavedEventViewDrag();});
}
