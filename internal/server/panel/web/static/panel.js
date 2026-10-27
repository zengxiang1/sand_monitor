(() => {
  const container = document.getElementById('panel-content');
  if (!container) return;
  let dirty = false;
  let pending = false;
  container.addEventListener('input', () => { dirty = true; });
  container.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) return;
    const source = document.getElementById(button.dataset.copy);
    if (source && navigator.clipboard) {
      await navigator.clipboard.writeText(source.textContent);
      button.textContent = '已复制';
    }
  });
  if (!container.dataset.refresh) return;
  const timer = setInterval(async () => {
    if (pending || dirty || document.hidden || container.querySelector('details[open]') || container.contains(document.activeElement) && document.activeElement.matches('input,textarea,select')) return;
    pending = true;
    try {
      const url = new URL(location.href);
      url.searchParams.set('fragment', '1');
      const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
      if (response.status === 401) { location.assign('/login'); return; }
      if (!response.ok) return;
      const documentFragment = new DOMParser().parseFromString(await response.text(), 'text/html');
      const refresh = documentFragment.querySelector('[data-panel-refresh]')?.dataset.panelRefresh === 'true';
      container.replaceChildren(...documentFragment.body.childNodes);
      if (!refresh) {
        delete container.dataset.refresh;
        clearInterval(timer);
      }
    } catch {
      const status = container.querySelector('[data-refresh-status]');
      if (status) status.textContent = '连接中断，正在重试';
    } finally { pending = false; }
  }, 5000);
})();
