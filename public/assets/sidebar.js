'use strict';

// Apply the saved desktop layout before the sidebar is painted.
(() => {
 const storageKey='fls.sidebarCollapsed';
 const root=document.documentElement;
 const desktop=window.matchMedia('(min-width: 901px)');
 let collapsed=false;
 try{collapsed=window.localStorage.getItem(storageKey)==='1';}catch{}
 root.classList.toggle('sidebar-collapsed',collapsed);

 function bindSidebar(){
  const sidebar=document.querySelector('.sidebar');
  const toggle=document.getElementById('desktop-sidebar-toggle');
  if(!sidebar||!toggle)return;

  const tooltip=document.createElement('div');
  tooltip.id='desktop-sidebar-tooltip';
  tooltip.className='sidebar-tooltip';
  tooltip.setAttribute('role','tooltip');
  tooltip.hidden=true;
  document.body.append(tooltip);
  const targets='#navigation .nav-item, .workspace-sidebar-search, .account-link, .logout, .collector-indicator, .brand';
  let hovered=null,focused=null,shown=null,descriptionBefore=null,titleBefore=null;

  function hideTooltip(){
   if(shown){
    if(descriptionBefore===null)shown.removeAttribute('aria-describedby');
    else shown.setAttribute('aria-describedby',descriptionBefore);
    // Workspace metadata can refresh a title while its menu is focused.
    if(titleBefore!==null&&!shown.hasAttribute('title'))shown.setAttribute('title',titleBefore);
   }
   tooltip.hidden=true;
   shown=null;
   descriptionBefore=null;
   titleBefore=null;
  }

  function tooltipText(target){
   if(target.matches('.collector-indicator'))return [...target.querySelectorAll('.collector-copy > *')].map(item=>item.textContent).join(' · ')||target.title;
   if(target.matches('.account-link'))return target.getAttribute('aria-label')||target.title;
   return target.title||target.getAttribute('aria-label')||target.textContent;
  }

  function showTooltip(){
   const target=hovered||focused;
   if(!desktop.matches||!collapsed||!target||!target.isConnected){hideTooltip();return;}
   if(shown===target&&!tooltip.hidden)return;
   hideTooltip();
   const text=String(tooltipText(target)||'').replace(/\s+/g,' ').trim();
   if(!text)return;
   shown=target;
   descriptionBefore=target.getAttribute('aria-describedby');
   target.setAttribute('aria-describedby',[descriptionBefore,tooltip.id].filter(Boolean).join(' '));
   titleBefore=target.getAttribute('title');
   target.removeAttribute('title');
   tooltip.textContent=text;
   tooltip.hidden=false;
   const itemBounds=target.getBoundingClientRect();
   const sidebarBounds=sidebar.getBoundingClientRect();
   tooltip.style.left=Math.round(sidebarBounds.right+10)+'px';
   tooltip.style.top=Math.round(Math.max(8,Math.min(window.innerHeight-tooltip.offsetHeight-8,itemBounds.top+(itemBounds.height-tooltip.offsetHeight)/2)))+'px';
  }

  function update(){
   root.classList.toggle('sidebar-collapsed',collapsed);
   const expanded=!desktop.matches||!collapsed;
   const label=expanded?'Sol menüyü daralt':'Sol menüyü genişlet';
   toggle.setAttribute('aria-expanded',String(expanded));
   toggle.setAttribute('aria-label',label);
   toggle.title=label;
   hideTooltip();
  }

  toggle.addEventListener('click',()=>{
   if(!desktop.matches)return;
   collapsed=!collapsed;
   try{window.localStorage.setItem(storageKey,collapsed?'1':'0');}catch{}
   update();
  });
  sidebar.addEventListener('pointerover',event=>{
   const target=event.target.closest(targets);
   if(target===hovered)return;
   hovered=target;
   showTooltip();
  });
  sidebar.addEventListener('pointerout',event=>{
   if(hovered?.contains(event.relatedTarget))return;
   hovered=null;
   showTooltip();
  });
  sidebar.addEventListener('focusin',event=>{focused=event.target.closest(targets);showTooltip();});
  sidebar.addEventListener('focusout',event=>{
   if(focused?.contains(event.relatedTarget))return;
   focused=null;
   showTooltip();
  });
  document.addEventListener('keydown',event=>{if(event.key==='Escape')hideTooltip();});
  window.addEventListener('resize',hideTooltip);
  window.addEventListener('scroll',hideTooltip,{capture:true,passive:true});
  desktop.addEventListener('change',()=>{
   const active=document.activeElement;
   update();
   // Let the existing mobile menu finish updating its inert state first.
   window.requestAnimationFrame(()=>{
    if(document.activeElement!==active&&document.activeElement!==document.body)return;
    if(!desktop.matches&&sidebar.contains(active)&&!sidebar.classList.contains('mobile-open'))document.getElementById('mobile-menu')?.focus();
    else if(desktop.matches&&active?.id==='mobile-menu')toggle.focus();
   });
  });
  window.addEventListener('storage',event=>{
   if(event.key!==storageKey&&event.key!==null)return;
   collapsed=event.key!==null&&event.newValue==='1';
   update();
  });
  update();
 }

 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bindSidebar,{once:true});
 else bindSidebar();
})();
