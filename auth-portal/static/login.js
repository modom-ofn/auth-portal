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

  async function checkSessionOnce() {
    try {
      const r = await fetch(`${base}/me`, { credentials: 'include' });
      if (!r.ok) return false;
      const j = await r.json().catch(() => ({}));
      return !!(j && (j.username || j.uuid));
    } catch (_) {
      return false;
    }
  }

  // Fallback: poll session for a few seconds. If logged in, redirect.
  function startSessionPoll() {
    const end = Date.now() + 12_000; // ~12s
    const timer = setInterval(async () => {
      if (Date.now() > end) { clearInterval(timer); return; }
      if (await checkSessionOnce()) {
        clearInterval(timer);
        redirectHome();
      }
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
      }

      // Primary: wait for postMessage from the popup/forward page
      const handler = (evt) => {
        try {
          if (evt.origin !== appOrigin) return;
          const data = evt.data || {};
          const ok = (data.type === 'auth-portal' || data.type === 'plex-auth') && data.ok === true;
          if (ok) {
            window.removeEventListener('message', handler);
            redirectHome();
          }
        } catch (e) {}
      };
      window.addEventListener('message', handler);

      // Backup: poll the session briefly in case message is missed
      startSessionPoll();

    } catch (e) {
      console.error(e);
      alert('Could not start login. Please try again.');
      btn.disabled = false;
    }
  }

  // *** NEW: On page load, if session is already valid, skip the login UI ***
  (async function autoForwardIfLoggedIn() {
    if (await checkSessionOnce()) {
      redirectHome();
      return;
    }
    // Not logged in → enable the button
    if (btn) btn.disabled = false;
  })();

  btn && btn.addEventListener('click', startWeb);
})();// Minimal, robust popup flow for dev-r2.
// Expects backend /auth/start-web to return { authUrl }.
// Listens for postMessage from /auth/forward and then navigates.

(() => {
  const btn = document.getElementById("plex-signin");
  if (!btn) return;

  function openPopup(url) {
    const w = 600, h = 700;
    const y = window.top.outerHeight / 2 + window.top.screenY - (h / 2);
    const x = window.top.outerWidth / 2 + window.top.screenX - (w / 2);
    return window.open(
      url,
      "plexAuth",
      `width=${w},height=${h},left=${x},top=${y},resizable=yes,scrollbars=yes`
    );
  }

  window.addEventListener("message", (ev) => {
    try {
      const d = ev.data || {};
      if (d && (d.type === "plex-auth" || d.type === "auth-portal") && d.ok) {
        const to = d.redirect || "/home";
        window.location.assign(to);
      }
    } catch (_) {}
  });

  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    try {
      const res = await fetch("/auth/start-web", { method: "POST" });
      if (!res.ok) throw new Error(`start-web ${res.status}`);
      const j = await res.json();
      const authUrl = j.authUrl || j.url || j.auth_url || j.location;
      if (!authUrl) throw new Error("no authUrl from server");
      const popup = openPopup(authUrl);

      // Fallback: if popup closes without a postMessage, try /home (server will redirect if no session)
      const iv = setInterval(() => {
        if (!popup || popup.closed) {
          clearInterval(iv);
          window.location.assign("/home");
        }
      }, 1200);
    } catch (err) {
      console.error(err);
      alert("Could not start login. Please try again.");
    } finally {
      btn.disabled = false;
    }
  });
})();