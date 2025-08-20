(function () {
  const baseMeta = (document.querySelector('meta[name="app-base-url"]') || {}).content || '';
  const base = baseMeta || '';
  // Derive the expected origin from BaseURL (fallback to current)
  let appOrigin = window.location.origin;
  try { appOrigin = new URL(base || window.location.href).origin; } catch (e) {}

  const btn = document.getElementById('startBtn');

  function openCenteredPopup(url, title) {
    const w = 520, h = 680;
    const y = window.top.outerHeight / 2 + window.top.screenY - (h / 2);
    const x = window.top.outerWidth / 2 + window.top.screenX - (w / 2);
    return window.open(url, title, `width=${w},height=${h},left=${x},top=${y},resizable,scrollbars`);
  }

  function redirectHome() {
    window.location = `${base}/home`;
  }

  // Fallback: poll session for a few seconds. If logged in, redirect.
  function startSessionPoll() {
    const end = Date.now() + 12_000; // ~12s
    const timer = setInterval(async () => {
      if (Date.now() > end) { clearInterval(timer); return; }
      try {
        const r = await fetch(`${base}/me`, { credentials: 'include' });
        if (r.ok) {
          const j = await r.json().catch(() => ({}));
          if (j && (j.username || j.uuid)) {
            clearInterval(timer);
            redirectHome();
          }
        }
      } catch (_) {}
    }, 800);
  }

  async function startWeb() {
    if (!btn) return;
    btn.disabled = true;

    try {
      const res = await fetch(`${base}/auth/start-web`, { method: 'POST', credentials: 'include' });
      if (!res.ok) throw new Error('start failed');
      const { authUrl } = await res.json();

      // Try popup first
      let popup = openCenteredPopup(authUrl, 'AuthPortal Login');
      if (!popup || popup.closed) {
        // Popup blocked → navigate current tab
        window.location = authUrl;
        // session poll still helps us get back
      }

      // Primary path: wait for postMessage from the popup/forward page
      const handler = (evt) => {
        try {
          if (evt.origin !== appOrigin) return;
          const data = evt.data || {};
          const ok = (data.type === 'plex-auth' || data.type === 'auth-portal') && data.ok === true;
          if (ok) {
            window.removeEventListener('message', handler);
            redirectHome();
          }
        } catch (e) {}
      };
      window.addEventListener('message', handler);

      // Backup path: poll the session briefly in case the message is missed
      startSessionPoll();

    } catch (e) {
      console.error(e);
      alert('Could not start login. Please try again.');
      btn.disabled = false;
    }
  }

  btn && btn.addEventListener('click', startWeb);
})();