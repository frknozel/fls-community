(() => {
  'use strict';
  const root = document.getElementById('operations-status');
  if (!root || document.documentElement.dataset.userRole !== 'admin') return;
  const heading = root.querySelector('[data-operations-heading]');
  const stamp = root.querySelector('[data-operations-stamp]');
  const alerts = root.querySelector('[data-operations-alerts]');
  const checks = root.querySelector('[data-operations-checks]');
  const growth = root.querySelector('[data-operations-growth]');
  const refresh = root.querySelector('[data-operations-refresh]');
  const allowedLinks = new Set(['/?view=system&system_tab=resources','/?view=settings&settings_tab=product','/?view=settings&settings_tab=archive','/?view=settings&settings_tab=storage','/?view=archive']);
  const states = {current:'Güncel',warning:'Dikkat',critical:'Müdahale gerekli',never:'Henüz çalışmadı',failed:'Başarısız',stuck:'Uzun sürüyor',running:'Çalışıyor',unknown:'Doğrulanamadı',overdue:'Gecikmiş',waiting:'Planlanan iş bekleniyor'};
  const labels = {system:'Sistem SSD’si',logs:'Log ve yedek diski',database:'MariaDB · tahmini boyut'};
  let busy = false;
  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  const bytes = n => Number.isFinite(n) ? `${(n / 1024 ** 3).toLocaleString('tr-TR', {maximumFractionDigits:1})} GiB` : 'Bilinmiyor';
  function render(data) {
    const measured = Date.parse(data.checked_at);
    if (data.schema !== 1 || !['healthy','warning','critical'].includes(data.state) || !Array.isArray(data.alerts) || !Array.isArray(data.checks) || !Number.isFinite(measured) || Math.abs(Date.now() - measured) > 180000) throw new Error('stale');
    root.dataset.state = data.state;
    heading.textContent = data.state === 'healthy' ? 'Sistem kontrolleri güncel' : `${data.alerts.length} yönetici uyarısı`;
    stamp.textContent = `Son kontrol ${new Date(measured).toLocaleTimeString('tr-TR', {timeZone:'Europe/Istanbul'})} · İstanbul`;
    alerts.replaceChildren();
    for (const item of data.alerts.slice(0, 30)) {
      const row = node('li', undefined, 'operations-alert');
      row.append(node('strong', item.title), node('span', item.detail));
      if (allowedLinks.has(item.url)) { const link = node('a','İlgili ayara git'); link.href = item.url; row.append(link); }
      alerts.append(row);
    }
    checks.replaceChildren();
    for (const item of data.checks.slice(0, 12)) {
      const row = node('li'); row.append(node('strong', item.label), node('span', states[item.state] || states.unknown));
      if (Number.isFinite(item.free_bytes) && Number.isFinite(item.total_bytes)) row.append(node('small', `${bytes(item.free_bytes)} boş / ${bytes(item.total_bytes)}`));
      checks.append(row);
    }
    growth.replaceChildren();
    for (const item of (data.history?.growth || []).slice(0, 3)) {
      if (!labels[item.role]) continue;
      const row = node('li'); row.append(node('strong', labels[item.role]));
      let description = `Geçmiş birikiyor · ${item.days_observed || 0}/7 günlük ölçüm`;
      if (item.state === 'growing') {
        description = `${bytes(item.bytes_per_day)} / gün artış`;
        if (Number.isFinite(item.estimated_days_remaining)) description += ` · yaklaşık ${item.estimated_days_remaining} gün alan`;
      } else if (item.state === 'stable_or_decreasing') description = 'Kullanım sabit veya azalıyor';
      else if (item.state === 'stale_history') description = 'Geçmiş ölçümü güncel değil; tahmin gösterilmiyor';
      row.append(node('span', description)); growth.append(row);
    }
  }
  async function load() {
    if (busy || document.hidden) return;
    busy = true; refresh.disabled = true;
    const controller = new AbortController(); let timer;
    try {
      const timeout = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, 12000); });
      const data = await Promise.race([timeout, (async () => {
        const response = await fetch('/api.php?route=operations_status', {signal:controller.signal, cache:'no-store', credentials:'same-origin'});
        if (!response.ok) throw new Error('request');
        return response.json();
      })()]);
      render(data);
    } catch (_) {
      root.dataset.state = 'unknown'; heading.textContent = 'Sistem kontrolü doğrulanamadı';
      stamp.textContent = 'Bağlantıyı kontrol edip yeniden deneyin.';
      alerts.replaceChildren(); checks.replaceChildren(); growth.replaceChildren();
    } finally { clearTimeout(timer); busy = false; refresh.disabled = false; }
  }
  refresh.addEventListener('click', load);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
  setInterval(load, 30000); load();
})();
