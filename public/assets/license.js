/* Community source license: all supported application features are free. */
function licenseTime(value){return Number.isInteger(value)?new Date(value*1000).toLocaleString('tr-TR',{timeZone:'Europe/Istanbul',hour12:false}):'—';}
function licensePanel(data){
 const valid=data?.mode==='community'&&data?.source_license==='Apache-2.0'&&data?.advanced_allowed===true;
 return `<section class="panel license-panel" id="license-panel" aria-labelledby="license-title"><div class="panel-heading"><h2 id="license-title">FLS Community · Apache-2.0</h2><span class="tag ${valid?'pass':'medium'}">${valid?'Açık kaynak':'Durum okunamadı'}</span></div><p>Desteklenen uygulama özellikleri süre veya ücretli aktivasyon kısıtlaması olmadan açıktır.</p><p>Harici zaman damgası hizmetinin hesabı ve kredileri ayrıca sağlanır.</p><a href="https://github.com/frknozel/fls-community/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">Apache-2.0 lisansı</a></section>`;
}
async function loadLicensePanel(root,signal){
 if(!root||document.documentElement.dataset.userRole!=='admin')return;
 const request=(root.flsLicenseRequest||0)+1;root.flsLicenseRequest=request;root.setAttribute('aria-busy','true');
 try{const data=await api('license_status',false,{},signal);if(signal?.aborted||!root.isConnected||root.flsLicenseRequest!==request)return;root.innerHTML=licensePanel(data);}
 catch(error){if(error.name!=='AbortError'&&root.isConnected&&root.flsLicenseRequest===request)root.innerHTML=licensePanel(null);}
 finally{if(root.isConnected&&root.flsLicenseRequest===request)root.setAttribute('aria-busy','false');}
}
