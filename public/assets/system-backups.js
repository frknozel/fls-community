'use strict';
(() => {
 const root = document.getElementById('system-backups-root');
 if (!root || document.documentElement.dataset.userRole !== 'admin') return;
 const settingsView = document.getElementById('view-settings');
 const settingsContent = document.getElementById('settings-content');
 const jobNames = {queued: 'Sırada', running: 'Çalışıyor', succeeded: 'Tamamlandı', failed: 'Başarısız'};
 const storageKey = 'fls-system-backup-request:' + (document.documentElement.dataset.userId || 'admin');
 let snapshot = null, observedAt = 0, reading = false, writing = false, readSequence = 0, readController = null;
 let draft = null, dirty = false, unresolved = null, acknowledgedJob = null, denied = false, error = '', notice = '', lastVisible = false, catalogSignature = '', encryptionSignature = '';
 let lastReadAt = 0, lastFresh = false;
 let recoveryDialog = null, recoverySelection = null, recoveryReturnFocus = null, recoveryController = null, recoverySequence = 0;

 const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char]));
 const admin = () => !denied && document.documentElement.dataset.userRole === 'admin';
 const active = () => admin() && !document.hidden && settingsView && !settingsView.classList.contains('hidden') && settingsContent?.querySelector('[data-settings-tab="archive"][aria-selected="true"]');
 const fresh = () => admin() && snapshot !== null && observedAt > 0 && Date.now() - observedAt < 30000;
 const positiveId = value => Number.isSafeInteger(value) && value > 0;
 const busyJob = () => acknowledgedJob || (snapshot?.active_job && ['queued', 'running'].includes(snapshot.active_job.status) ? snapshot.active_job : null);
 const canCreate = () => fresh() && snapshot.worker.available === true && !writing && !unresolved && !busyJob() && snapshot.encryption?.status !== 'error';
 const selectedTarget = () => snapshot?.destinations.find(target => String(target.id) === String(snapshot.settings.destination_id));
 const targetReady = target => !!target && Number(target.enabled) === 1 && target.check_status === 'ok' && Number(target.checked_revision) === Number(target.revision);
 function displayTime(value) {
  if (typeof value !== 'string' || !value) return '—';
  const date = new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : value.replace(' ', 'T') + 'Z');
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('tr-TR', {dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/Istanbul'}).format(date);
 }
 function size(bytes) {
  if (!Number.isFinite(Number(bytes)) || Number(bytes) < 0) return '—';
  const value = Number(bytes);
  return value >= 1073741824 ? (value / 1073741824).toLocaleString('tr-TR', {maximumFractionDigits: 2}) + ' GB' : (value / 1048576).toLocaleString('tr-TR', {maximumFractionDigits: 1}) + ' MB';
 }
 function remoteDirectory(target, directory) {
  if (!target) return 'Önce bir FTPS hedefi seçin.';
  const base = String(target.remote_path || '/').replace(/\/+$/, '');
  return base + '/' + String(directory || '') + '/';
 }
 function valid(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && value.settings &&
   positiveId(value.settings.revision) && typeof value.settings.db_dump_directory === 'string' && typeof value.settings.system_backup_directory === 'string' &&
   Array.isArray(value.destinations) && value.destinations.every(target => positiveId(target.id) && positiveId(target.revision) && typeof target.name === 'string' && typeof target.remote_path === 'string' && target.protocol === 'ftps') &&
   Array.isArray(value.backups) && value.backups.every(backup => positiveId(backup.id) && typeof backup.filename === 'string' && ['ready', 'missing'].includes(backup.status)) &&
   Array.isArray(value.jobs) && value.jobs.every(job => positiveId(job.id) && ['create', 'upload'].includes(job.action) && Object.hasOwn(jobNames, job.status) && typeof job.request_key === 'string') &&
   (value.active_job === null || (value.active_job && positiveId(value.active_job.id) && ['create', 'upload'].includes(value.active_job.action) && Object.hasOwn(jobNames, value.active_job.status))) &&
   value.worker && typeof value.worker.available === 'boolean' && typeof value.db_dump_schedule_enabled === 'boolean';
 }
 function persist(value) {
  unresolved = value;
  try { if (value) sessionStorage.setItem(storageKey, JSON.stringify(value)); else sessionStorage.removeItem(storageKey); } catch (_) { /* In-memory request identity still prevents an automatic duplicate. */ }
 }
 try {
  const value = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
  if (value && ['create', 'upload'].includes(value.action) && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.request_key) && (value.action === 'create' || [value.backup_id, value.settings_revision, value.destination_id, value.destination_revision].every(positiveId))) unresolved = value;
 } catch (_) { /* Corrupt storage cannot initiate a backup or transfer. */ }

 root.innerHTML = `<section class="panel system-backups-panel" aria-labelledby="system-backups-title"><div class="panel-heading"><div><h2 id="system-backups-title">FLS sistem yedeği</h2><p>Uygulama, kullanıcılar, bağlantılar ve ayarlar için kurtarma kopyası.</p></div><button type="button" class="button primary" id="system-backup-create" disabled>FLS System Backup</button></div><div class="system-backups-body"><p class="system-backups-intro">Log kayıtlarını içermeyen sistem yedeğini oluşturun, doğrulanmış dosyayı indirin veya seçtiğiniz FTPS hedefine aktarın. Kullanıcı hesapları, veritabanı yapısı ve yapılandırma korunur.</p><p class="system-backups-private">Yedek özel anahtarları ve bağlantı bilgilerini içerir. Dosyayı yalnız yetkili kişilerin erişebileceği bir yerde saklayın.</p><div id="system-backup-encryption" class="info-strip"></div><div class="system-backups-toolbar"><button type="button" class="button" id="system-backups-refresh">Listeyi yenile</button><span id="system-backups-status" role="status" aria-live="polite">Yedek bilgileri yükleniyor…</span></div><p id="system-backups-error" class="system-backups-error" role="alert" hidden></p><p id="system-backups-notice" class="system-backups-notice" role="status" hidden></p><button type="button" id="system-backups-replay" class="button" hidden>Aynı isteği yeniden gönder</button><div id="system-backup-catalog" class="system-backup-catalog"></div><form id="system-backup-path-form" class="system-backup-path-settings"><h3>Yedekleme dizinleri</h3><p>Klasörler, seçilen FTPS hedefinin ana dizini altında kullanılır. Sistem yedeğinin aktarımı düğmeyle başlatılır; günlük DB dump görevi kaydedilen hedef ve DB Dump dizinini kullanır.</p><div class="system-backup-fields"><label class="system-backup-field target" for="system-backup-target">Sistem yedeği ve günlük DB dump için FTPS hedefi<select id="system-backup-target" name="destination_id"><option value="">Hedef seçilmedi</option></select></label><label class="system-backup-field" for="system-backup-db-directory">DB Dump dizini<input id="system-backup-db-directory" name="db_dump_directory" value="DB-Dump" maxlength="400" required autocomplete="off"><small>Hedefteki konum: <strong id="system-backup-db-preview"></strong></small></label><label class="system-backup-field" for="system-backup-directory">FLS System Yedeği Dizini<input id="system-backup-directory" name="system_backup_directory" value="FLS-Backups" maxlength="400" required autocomplete="off"><small>Hedefteki konum: <strong id="system-backup-preview"></strong></small></label></div><p id="db-dump-schedule">Günlük DB dump durumu yükleniyor…</p><p id="db-dump-last-result"></p><div class="system-backup-path-actions"><button type="button" class="button" id="system-backup-path-reset" disabled>Kaydedilene dön</button><button type="submit" class="button primary" id="system-backup-path-save" disabled>Dizin ayarlarını kaydet</button></div></form><small class="system-backup-checked" id="system-backups-checked"></small></div></section>`;
 const find = id => root.querySelector('#' + id);
 const fields = {destination_id: find('system-backup-target'), db_dump_directory: find('system-backup-db-directory'), system_backup_directory: find('system-backup-directory')};
 function draftFrom(settings) { return {revision: settings.revision, destination_id: settings.destination_id === null ? '' : String(settings.destination_id), db_dump_directory: settings.db_dump_directory, system_backup_directory: settings.system_backup_directory}; }
 function sameSettings(left, right) { return String(left.destination_id ?? '') === String(right.destination_id ?? '') && left.db_dump_directory === right.db_dump_directory && left.system_backup_directory === right.system_backup_directory; }
 function fileLink(backup, key, part, label) {
  const value = backup[key];
  if (!fresh() || backup.status !== 'ready' || !backup.verified_at || !/^[a-f0-9]{64}$/.test(backup.sha256 || '') || typeof value !== 'string') return `<a aria-disabled="true">${label}</a>`;
  let url;
  try { url = new URL(value, location.origin); } catch (_) { return `<a aria-disabled="true">${label}</a>`; }
  const encrypted = ['encrypted', 'encrypted_sha256', 'encryption_report'].includes(part);
  const allowed = encrypted ? ['route', 'id', 'part', 'key_id'] : ['route', 'id', 'part'];
  const keys = [...url.searchParams.keys()];
  if (url.origin !== location.origin || url.username || url.password || url.hash || url.pathname !== '/api.php' || url.searchParams.get('route') !== 'system_backup_file' || url.searchParams.get('id') !== String(backup.id) || (url.searchParams.get('part') || 'archive') !== part || keys.some(key => !allowed.includes(key)) || keys.length !== new Set(keys).size || (encrypted && (!/^[a-f0-9]{32}$/.test(backup.key_id || '') || url.searchParams.get('key_id') !== backup.key_id))) return `<a aria-disabled="true">${label}</a>`;
  return `<a href="${esc(url.pathname + url.search)}" download referrerpolicy="no-referrer">${label}</a>`;
 }
 function transferFilename(backup) {
  const key = snapshot?.encryption?.active?.key_id;
  return snapshot?.encryption?.status === 'active' && /^[a-f0-9]{32}$/.test(key || '') ? backup.filename + '.' + key + '.age' : backup.filename;
 }
 function encryptionPanel() {
  const value = snapshot?.encryption;
  if (!value || value.status === 'disabled') return '<p><strong>FLS sistem yedeği şifrelemesi etkin değil.</strong> Mevcut yerel dosyalar ve FTPS aktarımı önceki biçimi kullanır.</p>';
  if (value.status === 'error') return '<p role="alert"><strong>FLS sistem yedeği şifreleme durumu doğrulanamadı.</strong> Yeni yedek ve aktarım işlemlerinden önce yapılandırma kontrol edilmeli. Şifresiz aktarıma otomatik dönüş yapılmaz.</p>';
  let html = value.status === 'active' ? '<p><strong>FLS sistem yedeği şifrelemesi etkin.</strong> Yeni sistem yedeklerine ayrı .age kopyası eklenir; FTPS aktarımında bu şifreli kopya kullanılır. Şifresiz yerel dosyalar korunur.<br>Kurtarma anahtarı kimliği: <code>' + esc(value.active?.key_id) + '</code></p>' : '';
  const pending = value.pending;
  if (pending && /^[a-f0-9]{32}$/.test(pending.key_id || '')) {
   let href = '';
   try { const url = new URL(pending.download_url, location.origin); const keys = [...url.searchParams.keys()]; if (url.origin === location.origin && !url.username && !url.password && !url.hash && url.pathname === '/api.php' && url.searchParams.get('route') === 'backup_encryption_key' && url.searchParams.get('key_id') === pending.key_id && keys.length === 2 && new Set(keys).size === 2) href = url.pathname + url.search; } catch (_) {}
   html += '<p><strong>' + (value.status === 'active' ? 'Yeni kurtarma anahtarının teslimi bekleniyor.' : 'Kurtarma anahtarının teslimi bekleniyor.') + '</strong> Anahtarı indirip sunucu dışında güvenle saklayın. İndirme, şifrelemeyi etkinleştirmez; teslim alındığı ayrıca onaylanmalıdır.<br>Anahtar kaybolursa şifreli kopya geri açılamaz. Kimlik: <code>' + esc(pending.key_id) + '</code></p>' + (href && fresh() ? '<a class="button" id="backup-encryption-key-download" href="' + esc(href) + '" download referrerpolicy="no-referrer">Kurtarma anahtarını indir</a>' : '');
  }
  return html + '<p>Bu özellik yalnız FLS sistem yedeğini kapsar. Günlük DB dump ve saatlik log arşivlerinin aktarım biçimini değiştirmez.</p>';
 }
 function uploadText(backup, target) {
  const upload = backup.last_upload;
  if (upload?.status === 'succeeded') return 'Son aktarım doğrulandı · ' + displayTime(upload.completed_at) + ' · ' + String(upload.remote_directory || '');
  if (upload?.status === 'failed') return 'Son aktarım tamamlanamadı. Sunucudaki doğrulanmış yerel yedek korunuyor.';
  if (dirty) return 'Yeni hedef veya dizini aktarımdan önce kaydedin.';
  if (!target) return 'Aktarmak için aşağıdan bir FTPS hedefi seçip kaydedin.';
  if (!targetReady(target)) return 'Aktarım için FTPS hedefinin etkin ve bağlantısının doğrulanmış olması gerekir.';
  return 'Hedef: ' + target.name + ' · ' + remoteDirectory(target, snapshot.settings.system_backup_directory) + transferFilename(backup);
 }
 function catalog() {
  const backups = snapshot?.backups || [], target = selectedTarget();
  if (!backups.length) return '<p class="system-backup-empty">Henüz kaydedilmiş bir FLS sistem yedeği yok. “FLS System Backup” ile ilk yedeği oluşturabilirsiniz.</p>';
  return backups.map(backup => {
   const verified = backup.status === 'ready' && !!backup.verified_at && /^[a-f0-9]{64}$/.test(backup.sha256 || '');
   const disabled = !canCreate() || !verified || dirty || !targetReady(target);
   const lastJob = snapshot.jobs.find(job => job.action === 'upload' && job.backup_id === backup.id);
   const copies = Array.isArray(backup.encrypted_copies) ? backup.encrypted_copies : [];
   const encryptedLinks = copies.map(copy => { const encrypted = {...backup, ...copy}; return '<div class="system-backup-artifacts"><span>Şifreli kopya · <code>' + esc(copy.key_id) + '</code></span>' + fileLink(encrypted, 'download_url', 'encrypted', 'Şifreli yedeği indir') + fileLink(encrypted, 'checksum_url', 'encrypted_sha256', 'Şifreli SHA-256') + fileLink(encrypted, 'report_url', 'encryption_report', 'Şifreleme bilgisi') + '</div>'; }).join('');
   return `<article class="system-backup-item" data-system-backup-id="${backup.id}"><div class="system-backup-title"><div><h3>${esc(backup.filename)}</h3><small>${esc(displayTime(backup.created_at))}${backup.created_by ? ' · ' + esc(backup.created_by) : ''}</small></div><span class="tag ${verified ? 'pass' : 'failed'}">${verified ? 'Doğrulandı' : 'Dosya kullanılamıyor'}</span></div><div class="system-backup-facts"><span>Boyut: <strong>${esc(size(backup.bytes))}</strong></span><span>Doğrulama: <strong>${esc(displayTime(backup.verified_at))}</strong></span>${lastJob ? `<span>Aktarım: <strong>${esc(jobNames[lastJob.status])}</strong></span>` : ''}</div><div class="system-backup-artifacts">${fileLink(backup, 'download_url', 'archive', 'Yedeği indir')}${fileLink(backup, 'checksum_url', 'sha256', 'SHA-256 özeti')}${fileLink(backup, 'report_url', 'report', 'Doğrulama raporu')}</div>${encryptedLinks}<div class="system-backup-recovery"><button type="button" class="button" data-system-backup-recovery="${backup.id}" ${!fresh() || !verified ? 'disabled' : ''}>Yedekten geri dön</button></div><div class="system-backup-upload"><div><p>${esc(uploadText(backup, target))}</p>${backup.last_upload?.status === 'succeeded' && target ? `<p>Yeni aktarım hedefi: ${esc(target.name)} · ${esc(remoteDirectory(target, snapshot.settings.system_backup_directory) + transferFilename(backup))}</p>` : ''}</div><button type="button" class="button" data-system-backup-upload="${backup.id}" ${disabled ? 'disabled' : ''}>FTPS’ye aktar</button></div></article>`;
  }).join('');
 }
 function render() {
  root.setAttribute('aria-busy', String(reading || writing));
  find('system-backup-create').disabled = !canCreate();
  find('system-backup-create').textContent = writing && unresolved?.action === 'create' ? 'İstek kaydediliyor…' : 'FLS System Backup';
  find('system-backups-refresh').disabled = reading || writing || !admin();
  find('system-backups-refresh').textContent = reading ? 'Yenileniyor…' : 'Listeyi yenile';
  const job = busyJob(), lastJob = snapshot?.jobs[0];
  find('system-backups-status').textContent = !admin() ? 'Yönetici oturumu gerekli.' : !fresh() ? 'Güncel durum alınamadı; listeyi yenileyin.' : unresolved ? 'Önceki isteğin sonucu kontrol edilmeli.' : job ? (job.action === 'create' ? 'Sistem yedeği ' : 'FTPS aktarımı ') + (job.status === 'running' ? 'hazırlanıyor…' : 'sırada bekliyor…') : !snapshot.worker.available ? 'Yedekleme hizmetine şu anda erişilemiyor.' : lastJob?.status === 'failed' ? 'Son ' + (lastJob.action === 'create' ? 'sistem yedeği' : 'FTPS aktarımı') + ' isteği tamamlanamadı. Yeni bir işlem başlatabilirsiniz.' : 'Yeni yedek oluşturabilirsiniz.';
  find('system-backups-error').textContent = error; find('system-backups-error').hidden = !error;
  find('system-backups-notice').textContent = notice; find('system-backups-notice').hidden = !notice;
  find('system-backups-replay').hidden = !unresolved; find('system-backups-replay').disabled = writing || !fresh() || !admin();
  for (const field of Object.values(fields)) field.disabled = !snapshot || writing || !admin();
  if (draft && snapshot) {
   const options = '<option value="">Hedef seçilmedi</option>' + snapshot.destinations.map(target => `<option value="${target.id}">${esc(target.name + (Number(target.enabled) === 1 ? '' : ' · Devre dışı'))}</option>`).join('');
   if (fields.destination_id.innerHTML !== options) fields.destination_id.innerHTML = options;
   for (const [name, input] of Object.entries(fields)) if (input.value !== String(draft[name])) input.value = String(draft[name]);
   const target = snapshot.destinations.find(target => String(target.id) === draft.destination_id);
   find('system-backup-db-preview').textContent = remoteDirectory(target, draft.db_dump_directory);
   find('system-backup-preview').textContent = remoteDirectory(target, draft.system_backup_directory);
   find('db-dump-schedule').textContent = snapshot.db_dump_schedule_enabled ? 'Günlük logsuz DB yedeği: 23:00 · FTPS aktarımı: 23:35 (İstanbul). Yerelde ve FTPS’de son 7 takvim günü saklanır.' : 'Günlük DB dump görevi şu anda etkin değil.';
   const create = snapshot.db_dump?.create, upload = snapshot.db_dump?.upload;
   const outcome = value => !value ? 'Henüz çalışmadı' : value.status === 'succeeded' ? ({current:'Tamamlandı · güncel',overdue:'Son başarılı kopya eski · gecikmiş',waiting:'Yeni görev bekleniyor · son başarılı kopya',unknown:'Zamanı veya doğrulaması bilinmiyor'}[value.age_state] || 'Tamamlandı · güncellik doğrulanamadı') + ' · ' + displayTime(value.completed_at_utc) : value.status === 'running' ? (value.age_state === 'stuck' ? 'Beklenenden uzun sürüyor' : 'Çalışıyor') : 'Tamamlanamadı · ' + displayTime(value.completed_at_utc);
   find('db-dump-last-result').textContent = 'Son DB yedeği: ' + outcome(create) + ' · Son FTPS aktarımı: ' + outcome(upload);
  }
  find('system-backup-path-save').disabled = !fresh() || writing || !dirty || !!unresolved || !!busyJob();
  find('system-backup-path-reset').disabled = !dirty || writing;
  const encryptionHtml = encryptionPanel();
  if (encryptionHtml !== encryptionSignature) { find('system-backup-encryption').innerHTML = encryptionHtml; encryptionSignature = encryptionHtml; }
  const html = snapshot ? catalog() : '<p class="system-backup-empty">Yedek kataloğu henüz yüklenmedi.</p>';
  if (html !== catalogSignature) { find('system-backup-catalog').innerHTML = html; catalogSignature = html; }
  find('system-backups-checked').textContent = observedAt ? 'Liste kontrolü: ' + displayTime(new Date(observedAt).toISOString()) : '';
  updateRecoveryDialog();
 }
 function recoveryAllowed() {
  const backup = snapshot?.backups.find(value => value.id === recoverySelection?.id);
  return !!active() && fresh() && backup?.status === 'ready' && !!backup.verified_at && /^[a-f0-9]{64}$/.test(backup.sha256 || '') && backup.sha256 === recoverySelection?.sha256;
 }
 function updateRecoveryDialog() {
  if (!recoveryDialog?.open) return;
  if (!active()) { recoveryDialog.close(); return; }
  recoveryDialog.querySelector('#system-recovery-kit-download').disabled = !recoveryAllowed() || !!recoveryController;
  if (!recoveryAllowed()) recoveryDialog.querySelector('#system-recovery-kit-status').textContent = 'Yedek veya oturum durumu değişti. Pencereyi kapatıp listeyi yenileyin.';
 }
 function openRecovery(id, button) {
  if (!active() || !fresh()) return;
  const backup = snapshot.backups.find(value => value.id === id);
  if (!backup || backup.status !== 'ready' || !backup.verified_at || !/^[a-f0-9]{64}$/.test(backup.sha256 || '')) return;
  if (!recoveryDialog) {
   recoveryDialog = document.createElement('dialog'); recoveryDialog.id = 'system-recovery-dialog'; recoveryDialog.className = 'system-recovery-dialog';
   recoveryDialog.setAttribute('aria-labelledby', 'system-recovery-title');
   recoveryDialog.innerHTML = '<h2 id="system-recovery-title">Yedekten geri dön</h2><p>Bu işlem, <strong>yeni Ubuntu 24.04 amd64 cihazda tek diskli kurtarma provası</strong> için başlangıç paketini indirir. Çalışan üretim sunucusunda geri yükleme başlatılmaz.</p><p>Yedek; FLS yazılımı, kullanıcılar, veritabanı yapısı ve ayarları içerir. <strong>İşletim sistemi imajı ve geçmiş log/arşiv verileri içermez.</strong></p><dl><dt>Seçilen yedek</dt><dd id="system-recovery-backup"></dd><dt>Kaynak SHA-256</dt><dd id="system-recovery-sha"></dd></dl><ol><li>Başlangıç paketini yeni Ubuntu cihazına kopyalayıp açın.</li><li><code>fls-recovery</code> klasöründe <code>sudo python3 start.py</code> komutunu çalıştırın.</li><li>Hedefte açılan sihirbazda seçilen yedeği ve gerekiyorsa dışarıda sakladığınız kurtarma anahtarını sağlayın.</li></ol><p>Başlangıç paketi yedek dosyasını veya özel kurtarma anahtarını içermez. Yedek dosyasını ayrıca indirin; anahtarı sunucu dışında saklamayı sürdürün.</p><p id="system-recovery-kit-status" role="status" aria-live="polite"></p><div class="system-recovery-actions"><button type="button" class="button" id="system-recovery-close">Kapat</button><button type="button" class="button primary" id="system-recovery-kit-download">Kurtarma başlangıç paketini indir</button></div>';
   document.body.append(recoveryDialog);
   recoveryDialog.querySelector('#system-recovery-close').onclick = () => recoveryDialog.close();
   recoveryDialog.querySelector('#system-recovery-kit-download').onclick = downloadRecoveryKit;
   recoveryDialog.addEventListener('close', () => { recoverySequence++; recoveryController?.abort(); recoveryController = null; recoverySelection = null; if (recoveryReturnFocus?.isConnected) recoveryReturnFocus.focus(); });
  }
  recoverySelection = {id, sha256: backup.sha256}; recoveryReturnFocus = button;
  recoveryDialog.querySelector('#system-recovery-backup').textContent = backup.filename;
  recoveryDialog.querySelector('#system-recovery-sha').textContent = backup.sha256;
  recoveryDialog.querySelector('#system-recovery-kit-status').textContent = '';
  recoveryDialog.showModal(); updateRecoveryDialog(); recoveryDialog.querySelector('#system-recovery-close').focus();
 }
 async function downloadRecoveryKit() {
  if (!recoveryAllowed() || recoveryController) return;
  const selection = {...recoverySelection}, sequence = ++recoverySequence, controller = new AbortController();
  recoveryController = controller; const timeout = setTimeout(() => controller.abort(), 45000);
  const status = recoveryDialog.querySelector('#system-recovery-kit-status'); status.textContent = 'Başlangıç paketi doğrulanıyor…'; updateRecoveryDialog();
  try {
   const url = '/api.php?route=system_recovery_kit&id=' + selection.id;
   const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}, signal: controller.signal});
   const value = await body(response);
   if (sequence !== recoverySequence || !recoveryDialog.open || !recoveryAllowed()) return;
   if (value.ready !== true || value.download_url !== url || value.filename !== 'fls-recovery-kit-' + selection.id + '.tar') throw new Error('Başlangıç paketi yanıtı doğrulanamadı.');
   const link = document.createElement('a'); link.href = url; link.download = value.filename; link.referrerPolicy = 'no-referrer'; link.hidden = true;
   document.body.append(link); link.click(); link.remove(); status.textContent = 'Başlangıç paketi indirmesi başlatıldı. Yedek dosyasını ayrıca indirmeyi unutmayın.';
  } catch (failure) {
   if (sequence === recoverySequence && recoveryDialog.open) status.textContent = denied ? 'Yönetici oturumu doğrulanamadı. Sayfayı yeniden yükleyin.' : failure.name === 'AbortError' ? 'Başlangıç paketi kontrolü zaman aşımına uğradı. Yeniden deneyebilirsiniz.' : failure.message || 'Başlangıç paketi indirilemedi. Yeniden deneyebilirsiniz.';
  } finally {
   clearTimeout(timeout); if (sequence === recoverySequence) { recoveryController = null; updateRecoveryDialog(); }
  }
 }
 function accept(value) {
  if (!valid(value)) throw new Error('Yedek bilgileri doğrulanamadı. Listeyi yenileyin.');
  if (snapshot && value.settings.revision < snapshot.settings.revision) return;
  snapshot = value; observedAt = Date.now();
  if (acknowledgedJob) {
   const job = value.jobs.find(job => job.request_key === acknowledgedJob.request_key);
   if (job) {
    acknowledgedJob = ['queued', 'running'].includes(job.status) ? job : null;
    if (job.status === 'succeeded') notice = job.action === 'create' ? 'Sistem yedeği oluşturuldu ve doğrulandı.' : 'FTPS aktarımı doğrulandı.';
    if (job.status === 'failed') { notice = ''; error = 'İşlem tamamlanamadı. Mevcut doğrulanmış yedekler korunuyor; yeni bir işlem başlatabilirsiniz.'; }
   }
  }
  if (!dirty || !draft) draft = draftFrom(value.settings);
  if (unresolved) {
   const job = value.jobs.find(job => job.request_key === unresolved.request_key);
   if (job) { notice = job.status === 'failed' ? 'Önceki istek tamamlanamadı. Yeni bir işlem başlatabilirsiniz.' : job.status === 'succeeded' ? (job.action === 'create' ? 'Sistem yedeği oluşturuldu ve doğrulandı.' : 'FTPS aktarımı doğrulandı.') : 'İstek sunucuda bulundu; işlem arka planda devam ediyor.'; persist(null); }
  }
  render();
 }
 async function body(response) {
  const value = await response.json();
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Sunucu yanıtı okunamadı.');
  if (response.status === 401 || response.status === 403) denied = true;
  if (!response.ok) { const failure = new Error(typeof value.error === 'string' ? value.error : 'İşlem tamamlanamadı.'); failure.status = response.status; throw failure; }
  return value;
 }
 async function refresh() {
  if (!admin() || reading || writing) return false;
  const sequence = ++readSequence, controller = new AbortController();
  readController = controller; reading = true; lastReadAt = Date.now(); render();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
   const response = await fetch('/api.php?route=system_backups', {credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
   const value = await body(response);
   if (sequence !== readSequence) return false;
   accept(value); return true;
  } catch (failure) {
   if (sequence === readSequence) { observedAt = 0; error = denied ? 'Yönetici oturumu doğrulanamadı. Sayfayı yeniden yükleyin.' : 'Yedek bilgileri alınamadı. Listeyi yenileyebilirsiniz.'; render(); }
   return false;
  } finally {
   clearTimeout(timeout);
   if (sequence === readSequence) { reading = false; readController = null; render(); }
  }
 }
 function startWrite() {
  readSequence++; readController?.abort(); readController = null; reading = false; writing = true; error = ''; notice = '';
 }
 function csrf() {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  if (!token) throw new Error('Oturum doğrulaması bulunamadı. Sayfayı yeniden yükleyin.');
  return token;
 }
 async function post(route, values, token) {
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 15000);
  try { return await body(await fetch('/api.php?route=' + route, {method: 'POST', credentials: 'same-origin', headers: {'X-CSRF-Token': token}, body: new URLSearchParams(values), signal: controller.signal})); }
  finally { clearTimeout(timeout); }
 }
 async function requestJob(action, backupId = null, replay = false) {
  if (!active() || writing || !fresh() || (!replay && !canCreate()) || (replay && !unresolved)) return;
  let descriptor, token;
  try {
   token = csrf();
   if (replay) descriptor = {...unresolved};
   else {
    if (!globalThis.crypto?.randomUUID) throw new Error('Güvenli istek kimliği üretilemedi. HTTPS bağlantısını kontrol edin.');
    descriptor = {action, request_key: crypto.randomUUID()};
    if (action === 'upload') {
     const backup = snapshot.backups.find(backup => backup.id === backupId), target = selectedTarget();
     if (dirty || !backup || backup.status !== 'ready' || !backup.verified_at || !targetReady(target)) return;
     Object.assign(descriptor, {backup_id: backupId, settings_revision: snapshot.settings.revision, destination_id: target.id, destination_revision: target.revision});
    }
   }
  } catch (failure) { error = failure.message; render(); return; }
  startWrite(); persist(descriptor); render();
  try {
   const {action: kind, ...values} = descriptor;
   const value = await post(kind === 'create' ? 'create_system_backup' : 'upload_system_backup', values, token);
   if (value.saved !== true || !value.job || value.job.request_key !== descriptor.request_key || !Object.hasOwn(jobNames, value.job.status)) throw new Error('İsteğin kaydedildiği doğrulanamadı. Listeyi yenileyin.');
   acknowledgedJob = ['queued', 'running'].includes(value.job.status) ? value.job : null;
   persist(null);
   notice = value.job.status === 'succeeded' ? (kind === 'create' ? 'Sistem yedeği oluşturuldu ve doğrulandı.' : 'FTPS aktarımı doğrulandı.') : value.job.status === 'failed' ? 'Bu istek daha önce tamamlanamadı. Yeni işlem için düğmeyi tekrar kullanabilirsiniz.' : 'İstek kaydedildi. İşlem arka planda devam eder; bu sayfayı açık tutmanız gerekmez.';
  } catch (failure) {
   if (Number.isInteger(failure.status) && failure.status >= 400 && failure.status < 500) persist(null);
   error = denied ? 'Yönetici oturumu doğrulanamadı. Sayfayı yeniden yükleyin.' : unresolved ? 'İstek sonucu doğrulanamadı. Liste yenilenerek kayıt kontrol edilecek. Otomatik tekrar gönderilmez.' : failure.message || 'İşlem tamamlanamadı.';
  } finally { writing = false; render(); await refresh(); }
 }
 async function savePaths(event) {
  event.preventDefault();
  if (!active() || !fresh() || writing || !dirty || unresolved || busyJob()) return;
  let token; try { token = csrf(); } catch (failure) { error = failure.message; render(); return; }
  const sent = {...draft}; startWrite(); render();
  try {
   const value = await post('save_system_backup_settings', sent, token);
   if (value.saved !== true || !value.settings || !positiveId(value.settings.revision) || value.settings.revision <= sent.revision) throw new Error('Ayarların kaydedildiği doğrulanamadı.');
   draft = draftFrom(value.settings); dirty = false; notice = 'Yedekleme dizinleri kaydedildi. Etkin günlük DB görevi bir sonraki çalışmada bu ayarları kullanır.';
  } catch (failure) { error = failure.message || 'Ayarlar kaydedilemedi. Listeyi yenileyip kaydı kontrol edin.'; }
  finally { writing = false; render(); await refresh(); }
 }
 for (const [name, input] of Object.entries(fields)) input.addEventListener(name === 'destination_id' ? 'change' : 'input', () => {
  if (!draft || writing) return; draft[name] = input.value; dirty = !sameSettings(draft, snapshot.settings); render();
 });
 find('system-backup-path-form').addEventListener('submit', savePaths);
 find('system-backup-path-reset').addEventListener('click', () => { if (!snapshot || writing) return; draft = draftFrom(snapshot.settings); dirty = false; error = ''; render(); });
 find('system-backup-create').addEventListener('click', () => requestJob('create'));
 find('system-backups-refresh').addEventListener('click', () => { error = ''; refresh(); });
 find('system-backups-replay').addEventListener('click', () => requestJob(unresolved?.action, unresolved?.backup_id, true));
 find('system-backup-catalog').addEventListener('click', event => {
  const recovery = event.target instanceof Element && event.target.closest('[data-system-backup-recovery]');
  if (recovery && !recovery.disabled) { openRecovery(Number(recovery.dataset.systemBackupRecovery), recovery); return; }
  const button = event.target instanceof Element && event.target.closest('[data-system-backup-upload]');
  if (button && !button.disabled) requestJob('upload', Number(button.dataset.systemBackupUpload));
 });
 function syncVisibility() {
  const show = !!active(); root.hidden = !show;
  if (show && !lastVisible) refresh();
  lastVisible = show;
  if (!show && recoveryDialog?.open) recoveryDialog.close();
 }
 if (settingsContent) new MutationObserver(syncVisibility).observe(settingsContent, {childList: true, subtree: true, attributes: true, attributeFilter: ['aria-selected', 'hidden']});
 if (settingsView) new MutationObserver(syncVisibility).observe(settingsView, {attributes: true, attributeFilter: ['class']});
 new MutationObserver(syncVisibility).observe(document.documentElement, {attributes: true, attributeFilter: ['data-user-role']});
 document.addEventListener('visibilitychange', syncVisibility);
 setInterval(() => {
  if (!active()) return;
  const isFresh = fresh(); if (lastFresh !== isFresh) render(); lastFresh = isFresh;
  if (!writing && Date.now() - lastReadAt >= (busyJob() || unresolved ? 3000 : 10000)) refresh();
 }, 1000);
 render(); syncVisibility();
})();
