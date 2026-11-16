'use strict';
(() => {
 const root = document.getElementById('power-management-root');
 if (!root || document.documentElement.dataset.userRole !== 'admin') return;

 const actions = {
  poweroff: {label: 'Sunucuyu kapat', title: 'Sunucu kapatılsın mı?', confirmation: 'KAPAT'},
  reboot: {label: 'Yeniden başlat', title: 'Sunucu yeniden başlatılsın mı?', confirmation: 'YENİDEN BAŞLAT'}
 };
 const blockingStatuses = new Set(['pending', 'waiting', 'submitted', 'uncertain']);
 const statusNames = {pending: 'İstek bekliyor', waiting: 'Kapatmaya hazırlanıyor', submitted: 'İşletim sistemine iletildi', failed: 'İşlem başarısız', rejected: 'İstek uygulanmadı', uncertain: 'Sonuç doğrulanamıyor'};
 const storageKey = 'fls-power-intent:' + (document.documentElement.dataset.userId || 'admin');
 let data = null, observedAt = 0, reading = false, saving = false, readSequence = 0;
 let intent = null, unresolved = null, note = '', transportError = false, accessDenied = false;
 let readController = null, lastVisible = false, rehearsalMode = false;

 function esc(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char])); }
 function visible() { return !document.hidden && !document.getElementById('view-system')?.classList.contains('hidden'); }
 function admin() { return !accessDenied && document.documentElement.dataset.userRole === 'admin'; }
 function readOnly() { return document.documentElement.dataset.recoveryRehearsal === '1' || rehearsalMode; }
 function fresh() { return !readOnly() && admin() && data?.available === true && data?.fresh === true && observedAt > 0 && Date.now() - observedAt < 30000; }
 function validSnapshot(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && value.schema === 1 &&
   (value.rehearsal === true || value.read_only === true || Number.isInteger(value.revision) && value.revision >= 0 && typeof value.boot_id === 'string' &&
   value.boot_id.length > 0 && (value.request === null || (value.request && typeof value.request === 'object' && !Array.isArray(value.request) &&
    Number.isInteger(value.request.id) && Object.hasOwn(actions, value.request.action) && Object.hasOwn(statusNames, value.request.status))));
 }
 function blocked() { return !fresh() || reading || saving || !!unresolved || blockingStatuses.has(data?.request?.status); }
 function time(value) {
  if (typeof value !== 'string' || !value) return '—';
  const date = new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : value.replace(' ', 'T') + 'Z');
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('tr-TR', {dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Europe/Istanbul'}).format(date);
 }
 function context() {
  return typeof state === 'object' ? [state.view, String(state.fgDevice ?? ''), state.systemTab].join('|') : location.pathname + location.search;
 }
 function storeAttempt(value) {
  unresolved = value;
  try { if (value) sessionStorage.setItem(storageKey, JSON.stringify(value)); else sessionStorage.removeItem(storageKey); } catch (_) { /* The in-memory duplicate lock still applies. */ }
 }
 try {
  const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
  if (saved && Object.hasOwn(actions, saved.action) && typeof saved.request_key === 'string' && typeof saved.boot_id === 'string' && Number.isInteger(saved.revision)) unresolved = saved;
 } catch (_) { /* Invalid or unavailable storage must not trigger an operation. */ }

 const dialog = document.createElement('dialog');
 dialog.id = 'power-dialog'; dialog.className = 'power-dialog';
 dialog.setAttribute('aria-labelledby', 'power-dialog-title');
 dialog.setAttribute('aria-describedby', 'power-dialog-description power-dialog-risk');
 document.body.append(dialog);
 dialog.addEventListener('cancel', event => { if (saving) event.preventDefault(); });
 dialog.addEventListener('close', () => { if (!dialog.open) { intent = null; dialog.innerHTML = ''; } });

 function message() {
  if (accessDenied) return 'Bu işlem için Yönetici yetkisi gerekiyor. Oturumunuzu yenileyin.';
  if (unresolved) return 'Önceki isteğin sonucu doğrulanamadı. Yeni işlem göndermeden önce sunucu durumunu yenileyin.';
  const request = data?.request;
  if (request?.status === 'submitted') return request.action === 'poweroff' ?
   'Kapatma komutu işletim sistemine iletildi. Sunucunun tamamen kapandığı bu arayüzden doğrulanamaz.' :
   'Yeniden başlatma komutu işletim sistemine iletildi. Sunucu döndüğünde sayfayı elle yenileyin.';
  if (request?.status === 'pending' || request?.status === 'waiting') return 'İstek kaydedildi. FLS servisleri ve işletim sistemi normal kapatma sırasıyla durdurulacak. İşlemin tamamlandığı henüz doğrulanmadı.';
  if (request?.status === 'uncertain') return 'İstek uygulamaya alındı; işletim sistemine iletilip iletilmediği doğrulanamıyor. Konsoldan kontrol edin.';
  if (request?.status === 'failed' || request?.status === 'rejected') return 'Son istek tamamlanamadı. Durumu yenileyip hata bilgisini değerlendirdikten sonra yeni bir işlem başlatabilirsiniz.';
  if (!fresh()) return transportError ? 'Sunucuya erişilemiyor. Bağlantının kesilmesi, sunucunun kapandığını veya yeniden başladığını doğrulamaz.' : 'Sunucu yönetiminin güncel durumu doğrulanıyor. İşlem düğmeleri doğrulama tamamlanınca açılır.';
  return 'İşlem seçildiğinde ayrıca yazılı onay istenir. Sunucu genelindeki tüm FLS servisleri etkilenir.';
 }
 function render() {
  if (!admin() && !accessDenied) { root.hidden = true; closeForContext(); return; }
  if (readOnly()) {
   if (dialog.open) dialog.close();
   root.setAttribute('aria-busy', 'false');
   root.innerHTML = '<section class="panel power-panel" aria-labelledby="power-panel-title"><div class="panel-heading"><div><h2 id="power-panel-title">Sunucu yönetimi</h2><p>Kurtarma provası: sunucu yönetimi kapalı.</p></div><span class="tag medium" role="status">Kurtarma provası</span></div><div class="power-panel-body"><p class="power-status" role="status">Bu prova panelinden işletim sistemi kapatılamaz veya yeniden başlatılamaz.</p><div class="power-actions"><button type="button" class="button power-off" data-power-action="poweroff" disabled>Sunucuyu kapat…</button><button type="button" class="button" data-power-action="reboot" disabled>Yeniden başlat…</button><button type="button" class="button" data-power-refresh disabled>Durumu yenile</button></div></div></section>';
   return;
  }
  root.setAttribute('aria-busy', String(reading || saving));
  const request = data?.request, disabled = blocked();
  const status = accessDenied ? 'Erişim yok' : !fresh() ? 'Durum doğrulanamıyor' : request ? statusNames[request.status] : 'İşlem için hazır';
  const bad = accessDenied || !fresh() || ['failed', 'rejected', 'uncertain'].includes(request?.status);
  root.innerHTML = `<section class="panel power-panel" aria-labelledby="power-panel-title"><div class="panel-heading"><div><h2 id="power-panel-title">Sunucu yönetimi</h2><p>İşletim sistemini ve FLS servislerini güvenli biçimde kapatın veya yeniden başlatın.</p></div><span class="tag ${bad ? 'failed' : request ? 'medium' : 'pass'}" role="status">${esc(status)}</span></div><div class="power-panel-body"><p class="power-scope">Yalnız Yönetici · Sunucu genelinde</p><p class="power-status" role="status" aria-live="polite">${esc(message())}</p>${request ? `<p class="power-request">Son istek: <strong>${esc(actions[request.action].label)}</strong> · ${esc(time(request.requested_at))}${request.requested_by ? ' · ' + esc(request.requested_by) : ''}</p>` : ''}${request?.error_code || data?.worker?.error_code ? `<p class="power-error">Hata: ${esc(request?.error_code || data?.worker?.error_code)}</p>` : ''}${note ? `<p class="power-note" role="status">${esc(note)}</p>` : ''}<div class="power-actions"><button type="button" class="button power-off" data-power-action="poweroff" ${disabled ? 'disabled' : ''}>Sunucuyu kapat…</button><button type="button" class="button" data-power-action="reboot" ${disabled ? 'disabled' : ''}>Yeniden başlat…</button><button type="button" class="button" data-power-refresh ${reading || saving || accessDenied ? 'disabled' : ''}>${reading ? 'Kontrol ediliyor…' : 'Durumu yenile'}</button>${request?.action === 'reboot' && blockingStatuses.has(request.status) ? '<button type="button" class="text-button" data-power-reload>Sayfayı yeniden yükle</button>' : ''}</div><p class="power-help">İşlem sırasında log alımı ve arayüz erişimi kesilir. Kapatılan sunucuyu yeniden açmak için fiziksel veya uzaktan güç erişimi gerekir.</p><small class="power-checked">Son kontrol: ${esc(time(data?.worker?.checked_at))}</small></div></section>`;
  root.querySelectorAll('[data-power-action]').forEach(button => button.addEventListener('click', () => open(button.dataset.powerAction)));
  root.querySelector('[data-power-refresh]')?.addEventListener('click', () => refresh(true));
  root.querySelector('[data-power-reload]')?.addEventListener('click', () => location.reload());
  updateDialog();
 }
 function accept(value, reconcile = false) {
  if (!validSnapshot(value)) throw new Error('Sunucu yönetimi yanıtı doğrulanamadı.');
  if (value.rehearsal === true || value.read_only === true) { rehearsalMode = true; data = value; observedAt = 0; render(); return; }
  if (data && value.boot_id === data.boot_id && value.revision < data.revision) return;
  data = value; observedAt = Date.now(); transportError = false;
  if (reconcile && unresolved && fresh()) {
   if (value.boot_id !== unresolved.boot_id) {
    note = 'Sunucuya yeni bir açılışla erişildi. Güncel durum yüklendi.'; storeAttempt(null);
   } else if (value.request?.request_key === unresolved.request_key) {
    note = 'Önceki istek sunucuda bulundu. Güncel sonucu yukarıda gösteriliyor.'; storeAttempt(null);
   } else if (value.revision >= unresolved.revision) {
    note = value.revision === unresolved.revision ? 'Gönderilen isteğe ait kayıt bulunamadı. Güncel durum yüklendi; yeni işlem için tekrar onay gerekir.' : 'Sunucudaki güncel istek yüklendi. Yeni işlem için güncel durumu kontrol edin.';
    storeAttempt(null);
   }
  }
  render();
 }
 async function getJson(response) {
  const value = await response.json();
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Sunucu yanıtı okunamadı.');
  return value;
 }
 async function refresh(reconcile = false) {
  if (readOnly()) { render(); return false; }
  if (reading || saving || !admin()) return false;
  const sequence = ++readSequence;
  reading = true; readController = new AbortController();
  const timeout = setTimeout(() => readController?.abort(), 10000);
  render();
  try {
   const response = await fetch('/api.php?route=power_status', {credentials: 'same-origin', cache: 'no-store', signal: readController.signal});
   const value = await getJson(response);
   if (sequence !== readSequence) return false;
   if (response.status === 401 || response.status === 403) { accessDenied = true; closeForContext(); throw new Error('Yönetici oturumu doğrulanamadı.'); }
   if (!response.ok) throw new Error(typeof value.error === 'string' ? value.error : 'Sunucu durumu okunamadı.');
   accept(value, reconcile || !!unresolved); return true;
  } catch (_) {
   if (sequence === readSequence) { transportError = true; observedAt = 0; render(); }
   return false;
  } finally {
   clearTimeout(timeout);
   if (sequence === readSequence) { reading = false; readController = null; render(); }
  }
 }
 function closeForContext() { if (dialog.open && !saving) dialog.close(); }
 function current(candidate) { return !!candidate && candidate === intent && dialog.open && admin() && visible() && context() === candidate.context; }
 function updateDialog() {
  if (!dialog.open || !intent) return;
  const confirm = dialog.querySelector('#power-confirm'), input = dialog.querySelector('#power-confirmation');
  if (!confirm || !input) return;
  const sameState = data?.revision === intent.revision && data?.boot_id === intent.boot_id;
  confirm.disabled = saving || intent.sent || !fresh() || !sameState || blockingStatuses.has(data?.request?.status) || input.value !== actions[intent.action].confirmation || !current(intent);
  if (!saving && (!sameState || !fresh()) && !intent.sent) {
   const error = dialog.querySelector('#power-dialog-error');
   error.textContent = 'Sunucunun durumu değişti veya güncelliği doğrulanamıyor. Pencereyi kapatıp durumu yenileyin.'; error.hidden = false;
  }
 }
 async function open(action) {
  if (!Object.hasOwn(actions, action) || blocked() || dialog.open || !visible() || !admin()) return;
  // Refresh before capturing the exact boot and revision the user will confirm.
  const initialContext = context();
  if (!await refresh() || blocked() || initialContext !== context() || !visible()) return;
  if (!globalThis.crypto?.randomUUID) { note = 'Güvenli istek kimliği üretilemedi. HTTPS bağlantısını kontrol edin.'; render(); return; }
  const selected = actions[action];
  intent = {action, revision: data.revision, boot_id: data.boot_id, request_key: crypto.randomUUID(), context: context(), sent: false};
  dialog.innerHTML = `<h2 id="power-dialog-title">${esc(selected.title)}</h2><span class="soft-tag power-dialog-scope">Sunucu genelinde · Tüm FortiGate’ler</span><p id="power-dialog-description">FLS servisleri normal kapatma sırasıyla durdurulur; bekleyen disk yazmaları tamamlanır ve işletim sistemi ${action === 'poweroff' ? 'kapanır' : 'yeniden başlatılır'}. ${action === 'poweroff' ? 'Sunucuyu tekrar açmak için fiziksel veya uzaktan güç erişimi gerekir.' : 'Sunucu açılana kadar arayüze erişilemez; döndüğünde sayfayı elle yenileyebilirsiniz.'}</p><p id="power-dialog-risk" class="power-risk">Log alımı kesilir. FortiGate’in kesinti sırasında oluşan logları sonradan yeniden göndermesi garanti değildir; bu aralıkta log kaybı oluşabilir.</p><form id="power-form"><label class="power-confirm-label" for="power-confirmation">Onaylamak için <strong>${esc(selected.confirmation)}</strong> yazın.</label><input id="power-confirmation" name="confirmation" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="24" aria-describedby="power-dialog-risk" required><p id="power-dialog-error" class="power-dialog-error" role="alert" hidden></p><div class="power-dialog-actions"><button type="button" class="button" id="power-cancel" autofocus>Vazgeç</button><button type="submit" class="button ${action === 'poweroff' ? 'power-off' : 'primary'}" id="power-confirm" disabled>${esc(selected.label)}</button></div></form>`;
  dialog.querySelector('#power-cancel').addEventListener('click', () => { if (!saving) dialog.close(); });
  dialog.querySelector('#power-confirmation').addEventListener('input', updateDialog);
  dialog.querySelector('#power-form').addEventListener('submit', event => { event.preventDefault(); submit(intent); });
  dialog.showModal(); dialog.querySelector('#power-cancel').focus(); render();
 }
 async function submit(candidate) {
  if (saving || !current(candidate) || candidate.sent || !fresh() || candidate.revision !== data?.revision || candidate.boot_id !== data?.boot_id || blocked()) return;
  const input = dialog.querySelector('#power-confirmation');
  if (input.value !== actions[candidate.action].confirmation) return;
  candidate.sent = true; saving = true; note = '';
  // Persist before the only POST so a reload cannot quietly bypass an unknown result.
  storeAttempt({action: candidate.action, revision: candidate.revision, boot_id: candidate.boot_id, request_key: candidate.request_key});
  const confirm = dialog.querySelector('#power-confirm'), cancel = dialog.querySelector('#power-cancel'), error = dialog.querySelector('#power-dialog-error');
  confirm.disabled = true; confirm.textContent = 'İstek kaydediliyor…'; cancel.disabled = true; input.disabled = true; error.hidden = true; render();
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 15000);
  try {
   const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
   if (!csrf) throw new Error('Oturum doğrulaması bulunamadı. Sayfayı yeniden yükleyin.');
   const response = await fetch('/api.php?route=request_power', {method: 'POST', credentials: 'same-origin', headers: {'X-CSRF-Token': csrf}, body: new URLSearchParams({action: candidate.action, revision: String(candidate.revision), boot_id: candidate.boot_id, request_key: candidate.request_key, confirmation: input.value}), signal: controller.signal});
   const value = await getJson(response);
   if (response.status === 401 || response.status === 403) accessDenied = true;
   if (!response.ok) {
    if (validSnapshot(value.power)) accept(value.power, true);
    throw new Error(typeof value.error === 'string' ? value.error : 'İstek kaydedilemedi. Güncel durumu kontrol edin.');
   }
   if (response.status !== 202 || !validSnapshot(value.power) || value.power.request?.request_key !== candidate.request_key) throw new Error('İsteğin kaydedildiği doğrulanamadı. Durumu yenileyin.');
   accept(value.power, true); dialog.close();
  } catch (failure) {
   if (dialog.open && candidate === intent) {
    error.textContent = (failure.name === 'AbortError' || failure instanceof TypeError ? 'İstek sonucu doğrulanamadı. Sunucu durumu kontrol ediliyor; otomatik tekrar gönderilmeyecek.' : failure.message) || 'İstek sonucu doğrulanamadı. Sunucu durumunu kontrol edin.';
    error.hidden = false;
   }
   transportError = true;
  } finally {
   clearTimeout(timeout); saving = false;
   if (dialog.open && candidate === intent) { cancel.disabled = false; confirm.disabled = true; confirm.textContent = actions[candidate.action].label; }
   render(); await refresh(true);
  }
 }
 const view = document.getElementById('view-system');
 if (view) new MutationObserver(() => {
  if (!visible()) closeForContext();
  if (visible() && !lastVisible) refresh(true);
  lastVisible = visible();
 }).observe(view, {attributes: true, attributeFilter: ['class']});
 document.addEventListener('click', event => { if (event.target instanceof Element && event.target.closest('[data-view],[data-workspace-tab]')) closeForContext(); }, true);
 window.addEventListener('popstate', closeForContext);
 document.addEventListener('visibilitychange', () => { if (visible()) refresh(true); });
 new MutationObserver(() => { if (!admin()) { closeForContext(); root.hidden = true; } }).observe(document.documentElement, {attributes: true, attributeFilter: ['data-user-role']});
 setInterval(() => { if (visible() && !dialog.open && !saving) refresh(true); }, 10000);
 let lastFresh = false;
 setInterval(() => {
  if (dialog.open && intent && (!visible() || context() !== intent.context)) closeForContext();
  const nowFresh = fresh();
  if (visible() && nowFresh !== lastFresh) render(); else updateDialog();
  lastFresh = nowFresh;
 }, 1000);
 render(); lastVisible = visible(); if (lastVisible) refresh(true);
})();
