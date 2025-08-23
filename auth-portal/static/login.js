// /static/login.js
(() => {
  function openPopup(url) {
    const w = 600, h = 700;
    const y = (window.top?.outerHeight || 800) / 2 + (window.top?.screenY || 0) - h / 2;
    const x = (window.top?.outerWidth || 1200) / 2 + (window.top?.screenX || 0) - w / 2;
    return window.open(
      url,
      "mediaAuth",
      `width=${w},height=${h},left=${x},top=${y},resizable=yes,scrollbars=yes`
    );
  }

  // Only accept messages from our own origin
  window.addEventListener("message", (ev) => {
    if (ev.origin !== window.location.origin) return;
    const d = ev.data || {};
    if (d && d.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "auth-portal")) {
      window.location.assign(d.redirect || "/home");
    }
  });

  async function startFlow(btn) {
    // Open placeholder popup synchronously (prevents popup blockers)
    let popup = openPopup("about:blank");
    try {
      if (popup?.document) {
        popup.document.write(`<!doctype html><meta charset="utf-8"><title>Starting sign-in…</title>
          <body style="font-family:system-ui;padding:1rem">Starting sign-in…</body>`);
        popup.document.close();
      }
    } catch {}

    btn.disabled = true;
    try {
      // Primary (Plex) path
      let authUrl = null;
      try {
        const res = await fetch("/auth/start-web", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Accept": "application/json" }
        });
        if (res.ok) {
          const j = await res.json().catch(() => ({}));
          authUrl = j.authUrl || j.url || j.location || null;
        }
      } catch {}

      // Fallback (Emby) path
      if (!authUrl) authUrl = "/auth/forward?emby=1";

      if (popup && !popup.closed) {
        try { popup.location.replace(authUrl); } catch { popup.location.href = authUrl; }
      } else {
        // Popup blocked → full-page navigation
        window.location.assign(authUrl);
        return;
      }

      // If user closes the popup, head to /home
      const iv = setInterval(() => {
        if (!popup || popup.closed) {
          clearInterval(iv);
          window.location.assign("/home");
        }
      }, 1200);

    } catch (err) {
      console.error(err);
      try {
        if (popup && !popup.closed && popup.document) {
          popup.document.body.innerHTML =
            `<p style="font-family:system-ui;color:#b91c1c">Could not start login. Please try again.</p>`;
        }
      } catch {}
      alert("Could not start login. Please try again.");
    } finally {
      btn.disabled = false;
    }
  }

  function bind() {
    const btn =
      document.getElementById("auth-signin") ||
      document.querySelector("[data-auth-signin]") ||
      document.querySelector(".auth-signin");
    if (!btn) return false;

    // If inside a form, prevent default submit
    const form = btn.closest("form");
    if (form) {
      form.addEventListener("submit", (e) => { e.preventDefault(); startFlow(btn); });
    }

    btn.addEventListener("click", (e) => { e.preventDefault(); startFlow(btn); });
    return true;
  }

  // Bind now; if not yet in DOM, bind on DOMContentLoaded; as a last resort, poll briefly
  if (!bind()) {
    document.addEventListener("DOMContentLoaded", bind);
    let tries = 0;
    const t = setInterval(() => { if (bind() || ++tries > 10) clearInterval(t); }, 150);
  }
})();