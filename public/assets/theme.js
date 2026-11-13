/* Account preference is rendered by PHP and applied before the first content paint. */
(()=>{
 'use strict';
 const root=document.documentElement,uid=root.dataset.userId||'',guestKey='fls.theme.v1';
 const key=uid?'fls.theme.user.'+uid:guestKey,media=matchMedia('(prefers-color-scheme: dark)');
 const valid=v=>['light','dark','system'].includes(v),normalize=v=>valid(v)?v:'system';
 const read=k=>{try{return localStorage.getItem(k);}catch(_){return null;}};
 const store=(k,v)=>{try{localStorage.setItem(k,v);}catch(_){/* Account saving works without browser storage. */}};
 let choice=normalize(uid?root.dataset.accountTheme:read(key));
 const migrate=Boolean(uid&&!valid(root.dataset.accountTheme)&&!read('fls.theme.account-migrated')&&valid(read(guestKey)));
 if(migrate)choice=normalize(read(guestKey));
 let dirty=false,saving=false;
 function message(text,error=false){
  document.querySelectorAll('[data-theme-status]').forEach(e=>e.textContent=text);
  document.querySelectorAll('[data-theme-retry]').forEach(e=>e.hidden=!error);
  document.querySelectorAll('[data-theme-choice]').forEach(e=>e.title=error?'Tema bu sayfada uygulandı, hesaba kaydedilemedi. Ünlem düğmesinden yeniden deneyin.':uid?'Tema hesabınıza kaydedilir; diğer bilgisayarlarda da yüklenir.':'Giriş ekranı tercihi bu tarayıcıda hatırlanır.');
 }
 function apply(){
  const theme=choice==='system'?(media.matches?'dark':'light'):choice;
  root.dataset.theme=theme;root.dataset.themePreference=choice;root.style.colorScheme=theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content',theme==='dark'?'#101a24':'#f3f6fb');
  document.querySelectorAll('[data-theme-choice]').forEach(e=>e.value=choice);
 }
 async function save(){
  if(!uid){store(key,choice);return;}
  dirty=true;if(saving)return;saving=true;document.querySelectorAll('[data-theme-choice]').forEach(e=>e.disabled=true);
  try{
   while(dirty){
    dirty=false;const sent=choice;message('Tema hesaba kaydediliyor.');
    const response=await fetch('/api.php?route=save_theme',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content},body:new URLSearchParams({theme:sent})});
    if(!response.ok)throw new Error('save');const data=await response.json();if(data.theme!==sent)throw new Error('save');
    root.dataset.accountTheme=sent;store('fls.theme.account-migrated','1');
    if(!dirty&&choice===sent){store(key,sent);message('Tema hesabınıza kaydedildi.');}
   }
  }catch(_){dirty=false;message('Tema bu sayfada uygulandı; hesaba kaydedilemedi. Yeniden deneyin.',true);}
  finally{saving=false;document.querySelectorAll('[data-theme-choice]').forEach(e=>e.disabled=false);}
 }
 apply();media.addEventListener('change',()=>{if(choice==='system')apply();});
 window.addEventListener('storage',e=>{if(e.key===key&&valid(e.newValue)&&!saving){choice=e.newValue;apply();message(uid?'Hesabınızın tema tercihi güncellendi.':'Tema güncellendi.');}});
 document.addEventListener('DOMContentLoaded',()=>{
  apply();message('');
  document.querySelectorAll('[data-theme-choice]').forEach(e=>e.addEventListener('change',()=>{choice=normalize(e.value);apply();save();}));
  document.querySelectorAll('[data-theme-retry]').forEach(e=>e.addEventListener('click',save));
  if(migrate)save();
 });
})();
