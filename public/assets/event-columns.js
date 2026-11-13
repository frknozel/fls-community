'use strict';
const eventColumnDefinitions=[['time','Son olay / tekrar',17],['outcome','Sonuç / modül',12],['source','Kaynak',13],['target','Hedef / uygulama',16],['policy','Policy ve profil',17],['reason','Gerekçe',18]];
const eventColumnKeys=eventColumnDefinitions.map(([key])=>key),eventColumnMin=80,eventColumnMax=1200;
let eventColumnsModel=null,eventColumnsDraft=null,eventLayoutDraft=null,eventColumnsSaving=false,eventColumnsError='',eventColumnsConflict=false,eventColumnsEditing=false,eventColumnDragged=null,eventResizeCancel=null;
function eventLayout(){return eventLayoutDraft||{order:eventColumnsModel?.order||eventColumnKeys,widths:eventColumnsModel?.widths||{},pinned:eventColumnsModel?.pinned||[]};}
function eventAcceptColumns(data){
 if(!Array.isArray(data.columns)||!data.columns.length||data.columns.some(key=>!eventColumnKeys.includes(key))||!Number.isInteger(data.revision))throw new Error('Sütun tercihi okunamadı.');
 const order=Array.isArray(data.order)?data.order:eventColumnKeys,widths=data.widths||{},pinned=data.pinned??[];
 if(!Array.isArray(pinned)||pinned.some(key=>!eventColumnKeys.includes(key))||new Set(pinned).size!==pinned.length)throw new Error('Sabit sütunlar okunamadı.');
 if(order.length!==6||new Set(order).size!==6||order.some(key=>!eventColumnKeys.includes(key))||typeof widths!=='object'||Array.isArray(widths)||Object.entries(widths).some(([key,value])=>!eventColumnKeys.includes(key)||!Number.isInteger(value)||value<eventColumnMin||value>eventColumnMax))throw new Error('Sütun düzeni okunamadı.');
 eventColumnsModel={...data,order:[...order],widths:{...widths},pinned:[...pinned]};
}
function eventSetLayout(order,widths,pinned=eventLayout().pinned){
 const normalized=Object.fromEntries(eventColumnKeys.filter(key=>Object.hasOwn(widths,key)).map(key=>[key,widths[key]]));
 const pins=eventColumnKeys.filter(key=>pinned.includes(key));
 eventLayoutDraft=JSON.stringify(pins)===JSON.stringify(eventColumnsModel.pinned)&&JSON.stringify(order)===JSON.stringify(eventColumnsModel.order)&&JSON.stringify(normalized)===JSON.stringify(eventColumnsModel.widths)?null:{order:[...order],widths:normalized,pinned:pins};
}
function eventVisualOrder(layout){return innerWidth<=900?layout.order:[...layout.order.filter(key=>layout.pinned.includes(key)),...layout.order.filter(key=>!layout.pinned.includes(key))];}
function eventPinColumns(root,headers,layout,selected){
 const cells=[...root.querySelectorAll('[data-event-column]')];
 for(const cell of cells){cell.classList.remove('event-column-pinned','event-column-pin-edge');cell.style.removeProperty('left');}
 let left=0,limited=false,last=null;
 if(innerWidth>900)for(const key of eventVisualOrder(layout).filter(key=>selected.includes(key)&&layout.pinned.includes(key))){
  const width=headers.find(th=>th.dataset.eventColumn===key)?.getBoundingClientRect().width||0;
  // Leave room to reach unpinned fields and the detail action even on narrow desktops.
  if(limited||left+width>root.clientWidth-100){limited=true;continue;}
  for(const cell of cells.filter(cell=>cell.dataset.eventColumn===key)){cell.classList.add('event-column-pinned');cell.style.left=left+'px';}
  left+=width;last=key;
 }
 if(last)for(const cell of cells.filter(cell=>cell.dataset.eventColumn===last))cell.classList.add('event-column-pin-edge');
 const notice=$('#event-pin-notice');if(notice){notice.hidden=!limited;notice.textContent=limited?'Dar alana sığmayan sabit sütunlar geçici olarak kayar; tercihiniz korunur.':'';}
}
function eventPlaceChildren(parent,nodes){if(nodes.some((node,i)=>parent.children[i]!==node))parent.append(...nodes);}
function eventColumnsControls(){
 const selected=eventColumnsDraft||eventColumnsModel?.columns||eventColumnKeys,form=$('#event-columns-form'),layout=eventLayout(),locked=eventColumnsSaving||!eventColumnsModel;
 if(!form)return;
 for(const input of form.querySelectorAll('[name="columns[]"]')){input.checked=selected.includes(input.value);input.disabled=locked||(selected.length===1&&input.checked);}
 const rows=layout.order.map(key=>form.querySelector('[data-column-option="'+key+'"]'));if(rows.every(Boolean))eventPlaceChildren($('#event-column-options'),rows);
 for(const[key]of eventColumnDefinitions){
  const input=form.querySelector('[data-column-width="'+key+'"]');if(document.activeElement!==input)input.value=layout.widths[key]??'';input.disabled=locked||eventColumnsConflict;
  const pin=form.querySelector('[data-column-pin="'+key+'"]');pin.disabled=locked||eventColumnsConflict;pin.setAttribute('aria-pressed',String(layout.pinned.includes(key)));pin.title=(layout.pinned.includes(key)?'Sabitlemeyi kaldır: ':'Solda sabitle: ')+eventColumnDefinitions.find(([k])=>k===key)[1];
  for(const button of form.querySelectorAll('[data-column-move="'+key+'"]'))button.disabled=locked||eventColumnsConflict||(Number(button.dataset.direction)<0?layout.order.indexOf(key)===0:layout.order.indexOf(key)===5);
 }
 $('#event-columns-save').disabled=locked||!(eventColumnsDraft||eventLayoutDraft)||eventColumnsConflict||!form.checkValidity();
 $('#event-columns-default').disabled=locked||eventColumnsConflict;
 $('#event-columns-reload').disabled=eventColumnsSaving;$('#event-columns-reload').hidden=!eventColumnsError&&!eventColumnsConflict;
 $('#event-columns-status').textContent=eventColumnsSaving?'Kaydediliyor…':eventColumnsError||((eventColumnsDraft||eventLayoutDraft)?'Kaydedilmemiş tercihler':eventColumnsModel?'Kaydedilmiş sütunlar gösteriliyor.':'Sütun tercihi yükleniyor…');
 $('#event-columns-status').classList.toggle('column-preference-error',Boolean(eventColumnsError));$('#event-columns-count').textContent=(eventColumnsModel?.columns.length||6)+'/6';
 $('#event-layout-save').hidden=!eventLayoutDraft;$('#event-layout-save').disabled=locked||eventColumnsConflict;
 $('#event-layout-status').textContent=eventColumnsSaving?'Kaydediliyor…':eventColumnsError?'Tercih kaydedilemedi':eventLayoutDraft?'Kaydedilmemiş düzen':eventColumnsModel&&(eventColumnsModel.pinned.length||Object.keys(eventColumnsModel.widths).length||JSON.stringify(eventColumnsModel.order)!==JSON.stringify(eventColumnKeys))?'Düzen hesabınıza kayıtlı':'';
 $('#event-layout-status').title=eventColumnsError;$('#event-layout-status').classList.toggle('column-preference-error',Boolean(eventColumnsError));
 document.querySelectorAll('#events-table th[data-event-column]').forEach(th=>{th.draggable=th.dataset.eventColumn!=='detail'&&!locked&&!eventColumnsConflict;th.querySelector('[data-column-resize]')?.setAttribute('aria-disabled',String(locked||eventColumnsConflict));});
 if(typeof savedEventViewsRender==='function')savedEventViewsRender();
}
async function loadEventColumns(signal,force=false){
 if(eventColumnsModel&&!force)return;
 try{
  const data=await api('event_columns',false,{},signal);if(signal?.aborted)return;
  eventAcceptColumns(data);if(force){eventColumnsDraft=null;eventLayoutDraft=null;}eventColumnsError='';eventColumnsConflict=false;applyEventColumns();
 }catch(e){if(e.name==='AbortError')return;eventColumnsError=eventColumnsModel?'Tercih yenilenemedi. Son yüklenen sütunlar ve yerel düzen korunuyor.':'Tercih okunamadı. Varsayılan sütunlar gösteriliyor; yeniden deneyin.';eventColumnsControls();}
}
function eventSizeColumns(){
 const root=$('#events-table'),table=root.querySelector('table');if(!table)return;
 const layout=eventLayout(),selected=eventColumnsModel?.columns||eventColumnKeys,keys=eventVisualOrder(layout).filter(key=>selected.includes(key)),headers=[...table.querySelectorAll('thead th')];
 let group=table.querySelector('colgroup');if(!group){group=document.createElement('colgroup');table.prepend(group);}
 group.replaceChildren();
 if(innerWidth<=900){table.style.width='100%';table.style.minWidth='';headers.forEach(th=>th.style.width='');eventPinColumns(root,headers,layout,selected);return;}
 const definitions=new Map(eventColumnDefinitions.map(([key,,weight])=>[key,weight])),weight=keys.reduce((sum,key)=>sum+definitions.get(key),7),custom=Object.keys(layout.widths).length>0;
 const widths=keys.map(key=>custom?(layout.widths[key]??Math.max(eventColumnMin,Math.min(eventColumnMax,Math.round(root.clientWidth*definitions.get(key)/weight)))):definitions.get(key)/weight*100);
 const total=widths.reduce((sum,width)=>sum+width,0),detail=custom?Math.max(84,root.clientWidth-total):7/weight*100;
 if(custom){table.style.width=(total+detail)+'px';table.style.minWidth=(total+detail)+'px';}else{table.style.width='100%';table.style.minWidth='';}
 [...keys,'detail'].forEach((key,i)=>{const value=(i===keys.length?detail:widths[i])+(custom?'px':'%'),col=document.createElement('col');col.style.width=value;group.append(col);const th=headers.find(th=>th.dataset.eventColumn===key);if(th)th.style.width=value;});
 eventPinColumns(root,headers,layout,selected);
 for(const th of headers){const handle=th.querySelector('[data-column-resize]');if(handle){const width=Math.round(th.getBoundingClientRect().width);handle.setAttribute('aria-valuenow',String(Math.max(eventColumnMin,Math.min(eventColumnMax,width))));handle.setAttribute('aria-valuetext',(Object.hasOwn(layout.widths,th.dataset.eventColumn)?'':'Otomatik, ')+width+' piksel');}}
}
function eventCaptureWidths(){
 const widths={...eventLayout().widths};
 document.querySelectorAll('#events-table th[data-event-column]:not([hidden])').forEach(th=>{if(th.dataset.eventColumn!=='detail')widths[th.dataset.eventColumn]=Math.max(eventColumnMin,Math.min(eventColumnMax,Math.round(th.getBoundingClientRect().width)));});
 return widths;
}
function eventClearDrag(){eventColumnsEditing=false;eventColumnDragged=null;document.querySelectorAll('#events-table th').forEach(th=>{th.classList.remove('column-dragging');delete th.dataset.dropSide;});}
function eventMoveColumn(key,target,after=false,auto=false){
 if(!eventColumnsModel||eventColumnsSaving||eventColumnsConflict||key===target)return;
 const layout=eventLayout();if(auto&&layout.pinned.includes(key)!==layout.pinned.includes(target))return;const order=layout.order.filter(item=>item!==key),index=order.indexOf(target);if(index<0)return;
 order.splice(index+(after?1:0),0,key);eventSetLayout(order,layout.widths);applyEventColumns();if(auto)saveEventColumns(true);
}
function eventResizeStart(event,key,handle){
 if(event.button!==0||!eventColumnsModel||eventColumnsSaving||eventColumnsConflict||innerWidth<=900)return;
 event.preventDefault();event.stopPropagation();$('#event-column-menu').open=false;
 const before=eventLayoutDraft?{order:[...eventLayoutDraft.order],widths:{...eventLayoutDraft.widths},pinned:[...eventLayoutDraft.pinned]}:null,layout=eventLayout(),order=[...layout.order],widths=eventCaptureWidths(),start=event.clientX,startWidth=handle.parentElement.getBoundingClientRect().width;
 let moved=false,done=false;eventColumnsEditing=true;document.body.classList.add('column-resizing');handle.parentElement.draggable=false;handle.setPointerCapture(event.pointerId);
 const move=next=>{if(next.pointerId!==event.pointerId)return;const width=Math.max(eventColumnMin,Math.min(eventColumnMax,Math.round(startWidth+next.clientX-start)));if(Math.abs(next.clientX-start)<2&&!moved)return;moved=true;widths[key]=width;eventSetLayout(order,widths);eventSizeColumns();eventColumnsControls();handle.parentElement.draggable=false;};
 const end=(next,cancel=false)=>{if(done||next&&next.pointerId!==event.pointerId)return;done=true;handle.removeEventListener('pointermove',move);handle.removeEventListener('pointerup',up);handle.removeEventListener('pointercancel',abort);handle.removeEventListener('lostpointercapture',abort);eventColumnsEditing=false;eventResizeCancel=null;document.body.classList.remove('column-resizing');if(cancel)eventLayoutDraft=before;if(handle.hasPointerCapture(event.pointerId))handle.releasePointerCapture(event.pointerId);eventSizeColumns();eventColumnsControls();if(moved&&!cancel)saveEventColumns(true);};
 const up=next=>end(next),abort=next=>end(next,true);eventResizeCancel=()=>end(null,true);
 handle.addEventListener('pointermove',move);handle.addEventListener('pointerup',up);handle.addEventListener('pointercancel',abort);handle.addEventListener('lostpointercapture',abort);
}
function eventBuildHeader(th,key,label){
 if(key==='detail'||th.querySelector('.event-column-label'))return;
 const grip=document.createElement('span');grip.className='event-column-grip';grip.textContent='⠿';grip.setAttribute('aria-hidden','true');
 const text=document.createElement('span');text.className='event-column-label';text.textContent=label;
 const handle=document.createElement('span');handle.className='event-column-resize';handle.dataset.columnResize=key;handle.tabIndex=0;handle.setAttribute('role','separator');handle.setAttribute('aria-orientation','vertical');handle.setAttribute('aria-label',label+' sütununun genişliği');handle.setAttribute('aria-valuemin',eventColumnMin);handle.setAttribute('aria-valuemax',eventColumnMax);handle.title='Genişliği sürükleyerek veya ok tuşlarıyla ayarlayın. Çift tık: otomatik genişlik.';
 th.replaceChildren(grip,text,handle);th.title=label+' · Sıralamak için başlığı sürükleyin';
 th.ondragstart=event=>{if(event.target.closest('[data-column-resize]')||eventColumnsSaving||eventColumnsConflict){event.preventDefault();return;}$('#event-column-menu').open=false;eventColumnDragged=key;eventColumnsEditing=true;event.dataTransfer.setData('text/plain',key);event.dataTransfer.effectAllowed='move';th.classList.add('column-dragging');};
 th.ondragover=event=>{if(!eventColumnDragged||eventColumnDragged===key||eventLayout().pinned.includes(eventColumnDragged)!==eventLayout().pinned.includes(key))return;event.preventDefault();event.dataTransfer.dropEffect='move';document.querySelectorAll('#events-table th[data-drop-side]').forEach(item=>delete item.dataset.dropSide);const rect=th.getBoundingClientRect();th.dataset.dropSide=event.clientX>rect.left+rect.width/2?'after':'before';const root=$('#events-table'),area=root.getBoundingClientRect();if(event.clientX>area.right-28)root.scrollLeft+=18;else if(event.clientX<area.left+28)root.scrollLeft-=18;};
 th.ondrop=event=>{if(!eventColumnDragged)return;event.preventDefault();const dragged=eventColumnDragged,after=th.dataset.dropSide==='after';eventClearDrag();eventMoveColumn(dragged,key,after,true);};th.ondragend=eventClearDrag;
 handle.onpointerdown=event=>eventResizeStart(event,key,handle);
 handle.onkeydown=event=>{if(!['ArrowLeft','ArrowRight','Home','End','Delete','Backspace'].includes(event.key))return;event.preventDefault();if(!eventColumnsModel||eventColumnsSaving||eventColumnsConflict)return;const layout=eventLayout(),widths=eventCaptureWidths(),width=th.getBoundingClientRect().width;if(['Delete','Backspace'].includes(event.key))delete widths[key];else widths[key]=Math.max(eventColumnMin,Math.min(eventColumnMax,event.key==='Home'?eventColumnMin:event.key==='End'?eventColumnMax:Math.round(width)+(event.key==='ArrowRight'?10:-10)));eventSetLayout(layout.order,widths);eventSizeColumns();eventColumnsControls();saveEventColumns(true);};
 handle.ondblclick=event=>{event.preventDefault();event.stopPropagation();if(!eventColumnsModel||eventColumnsSaving||eventColumnsConflict)return;const layout=eventLayout(),widths={...layout.widths};delete widths[key];eventSetLayout(layout.order,widths);eventSizeColumns();eventColumnsControls();saveEventColumns(true);};
}
function applyEventColumns(){
 const root=$('#events-table'),selected=eventColumnsModel?.columns||eventColumnKeys,layout=eventLayout(),keys=[...eventColumnKeys,'detail'],order=[...eventVisualOrder(layout),'detail'];
 const row=root.querySelector('thead tr');
 if(row){const cells=[...row.children];cells.forEach((cell,i)=>{cell.dataset.eventColumn||=keys[i];cell.scope='col';cell.hidden=cell.dataset.eventColumn!=='detail'&&!selected.includes(cell.dataset.eventColumn);const definition=eventColumnDefinitions.find(([key])=>key===cell.dataset.eventColumn);eventBuildHeader(cell,cell.dataset.eventColumn,definition?.[1]||'İşlem');});eventPlaceChildren(row,order.map(key=>cells.find(cell=>cell.dataset.eventColumn===key)));}
 root.querySelectorAll('tr[data-event]').forEach(row=>{const cells=[...row.cells];cells.forEach((cell,i)=>{cell.dataset.eventColumn||=keys[i];cell.hidden=cell.dataset.eventColumn!=='detail'&&!selected.includes(cell.dataset.eventColumn);});eventPlaceChildren(row,order.map(key=>cells.find(cell=>cell.dataset.eventColumn===key)));});
 root.querySelectorAll('.mail-preview>td,.table-empty>td').forEach(cell=>cell.colSpan=selected.length+1);eventSizeColumns();eventColumnsControls();
}
async function saveEventColumns(layoutOnly=false){
 if(!eventColumnsModel||eventColumnsSaving||eventColumnsConflict||!(eventLayoutDraft||!layoutOnly&&eventColumnsDraft))return;
 const layout=eventLayout(),body=new FormData();(layoutOnly?eventColumnsModel.columns:eventColumnsDraft||eventColumnsModel.columns).forEach(key=>body.append('columns[]',key));layout.order.forEach(key=>body.append('order[]',key));body.set('widths',JSON.stringify(layout.widths));body.set('pinned',JSON.stringify(layout.pinned));body.set('revision',String(eventColumnsModel.revision));eventColumnsSaving=true;eventColumnsError='';eventColumnsControls();
 try{
  const response=await fetch('/api.php?route=save_event_columns',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':$('meta[name="csrf-token"]').content},body});
  if(response.status===401){location.href='/';return;}
  const data=await response.json();if(response.status===409){eventAcceptColumns(data);eventColumnsConflict=true;applyEventColumns();}
  if(!response.ok)throw new Error(data.error||'Sütun tercihi kaydedilemedi.');
  eventAcceptColumns(data);eventLayoutDraft=null;if(!layoutOnly)eventColumnsDraft=null;eventColumnsError='';applyEventColumns();
  if(!layoutOnly){$('#event-column-menu').open=false;$('#event-column-menu summary').focus({preventScroll:true});}toast(layoutOnly?'Tablo düzeni hesabınıza kaydedildi.':'Sütun tercihiniz hesabınıza kaydedildi.');
 }catch(e){eventColumnsError=e instanceof TypeError?'Kaydedilemedi. Yerel düzen ve seçimleriniz korunuyor; yeniden deneyin.':e.message;}
 finally{eventColumnsSaving=false;eventColumnsControls();}
}
function bindEventColumns(){
 const form=$('#event-columns-form'),menu=$('#event-column-menu');
 form.innerHTML='<div id="event-column-options">'+eventColumnDefinitions.map(([key,label])=>`<div class="event-column-option" data-column-option="${key}"><label><input type="checkbox" name="columns[]" value="${key}"><span>${label}</span></label><div class="event-column-layout-fields"><button type="button" class="column-pin" data-column-pin="${key}" aria-pressed="false" aria-label="${label}: solda sabitle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m8 3 8 0-1 6 3 4v2H6v-2l3-4-1-6Zm4 12v6"/></svg></button><button type="button" class="column-move" data-column-move="${key}" data-direction="-1" aria-label="${label} sütununu sola taşı" title="Sola taşı">↑</button><button type="button" class="column-move" data-column-move="${key}" data-direction="1" aria-label="${label} sütununu sağa taşı" title="Sağa taşı">↓</button><input type="number" data-column-width="${key}" min="80" max="1200" step="1" inputmode="numeric" placeholder="Oto" aria-label="${label} genişliği (piksel)"><span>px</span></div></div>`).join('')+'</div><p class="event-columns-help">İğne düğmesi sütunu solda sabitler; sabit sütunlar kendi sıralarıyla solda toplanır. En az bir bilgi sütunu seçin. İncele sağda kalır. Genişlik: 80–1.200 px; boş bırakırsanız otomatik. Menüdeki değişiklikleri aşağıdan kaydedin.</p><p id="event-columns-status" role="status"></p><div class="event-columns-buttons"><button type="button" class="text-button" id="event-columns-default">Varsayılana dön</button><button type="submit" class="button primary" id="event-columns-save">Uygula ve kaydet</button></div><button type="button" class="text-button" id="event-columns-reload" hidden>Güncel seçimi yükle</button>';
 form.onchange=event=>{if(!event.target.matches('[name="columns[]"]'))return;const selected=eventColumnKeys.filter(key=>form.querySelector('input[value="'+key+'"]').checked);eventColumnsDraft=JSON.stringify(selected)===JSON.stringify(eventColumnsModel?.columns)?null:selected;eventColumnsControls();};
 form.oninput=event=>{const input=event.target;if(!input.matches('[data-column-width]')||!eventColumnsModel)return;if(input.validity.valid){const layout=eventLayout(),widths={...layout.widths};if(input.value==='')delete widths[input.dataset.columnWidth];else widths[input.dataset.columnWidth]=Number(input.value);eventSetLayout(layout.order,widths);eventSizeColumns();}eventColumnsControls();};
 form.querySelectorAll('[data-column-pin]').forEach(button=>button.onclick=()=>{const layout=eventLayout(),key=button.dataset.columnPin,pinned=layout.pinned.includes(key)?layout.pinned.filter(item=>item!==key):[...layout.pinned,key];eventSetLayout(layout.order,layout.widths,pinned);applyEventColumns();});
 form.querySelectorAll('[data-column-move]').forEach(button=>button.onclick=()=>{const layout=eventLayout(),index=layout.order.indexOf(button.dataset.columnMove),direction=Number(button.dataset.direction),target=layout.order[index+direction];if(target)eventMoveColumn(button.dataset.columnMove,target,direction>0);const next=form.querySelector('[data-column-option="'+button.dataset.columnMove+'"]');(button.disabled?next.querySelector('[data-column-move]:not([disabled])')||next.querySelector('[data-column-width]'):button).focus({preventScroll:true});});
 $('#event-columns-default').onclick=()=>{eventColumnsDraft=JSON.stringify(eventColumnKeys)===JSON.stringify(eventColumnsModel.columns)?null:[...eventColumnKeys];eventSetLayout(eventColumnKeys,{},[]);applyEventColumns();};
 $('#event-columns-reload').onclick=()=>loadEventColumns(undefined,true);
 $('#event-layout-save').onclick=()=>saveEventColumns(true);
 form.onsubmit=event=>{event.preventDefault();if(form.reportValidity())saveEventColumns();};
 document.addEventListener('click',event=>{if(!menu.contains(event.target))menu.open=false;});
 document.addEventListener('keydown',event=>{if(event.key==='Escape'&&eventResizeCancel){eventResizeCancel();event.preventDefault();event.stopPropagation();}});
 menu.addEventListener('keydown',event=>{if(event.key==='Escape'){menu.open=false;menu.querySelector('summary').focus();event.preventDefault();event.stopPropagation();}});
 let lastWidth=-1,lastMobile=null;new ResizeObserver(()=>{const width=$('#events-table').clientWidth,mobile=innerWidth<=900;if(width!==lastWidth||mobile!==lastMobile){lastWidth=width;lastMobile=mobile;if(!eventColumnsEditing)applyEventColumns();}}).observe($('#events-table'));
 eventColumnsControls();
}
