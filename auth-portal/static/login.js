// /static/login.js
(() => {
  const btn = document.getElementById("auth-signin") ||
              document.querySelector("[data-auth-signin]") ||
              document.querySelector(".auth-signin");
  if (!btn) return;

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

  // Only accept messages from our origin
  window.addEventListener("message", (ev) => {
    if (ev.origin !== window.location.origin) return;
    const d = ev.data || {};
    if (d && d.ok && (d.type === "plex-auth" || d.type === "emby-auth" || d.type === "auth-portal")) {
      window.location.assign(d.redirect || "/home");
    }
  });

  async function startFlow() {
    // Open placeholder popup *synchronously* to preserve user gesture
    let popup = openPopup("about:blank");
    try {
      if (popup?.document) {
        popup.document.write(
          `<!doctype html><meta charset="utf-8"><title>Starting sign-in…</title>
           <body style="font-family:system-ui;padding:1rem;line-height:1.4">
             <p>Starting sign-in…</p>
           </body>`
        );
        popup.document.close();
      }
    } catch {}

    btn.disabled = true;
    try {
      // Primary path: Plex start endpoint
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

      // Fallback path: Emby local popup page
      if (!authUrl) {
        authUrl = "/auth/forward?emby=1";
      }

      if (popup && !popup.closed) {
        try { popup.location.replace(authUrl); } catch { popup.location.href = authUrl; }
      } else {
        // Popup was blocked → degrade to full-page navigation
        window.location.assign(authUrl);
        return;
      }

      // If user closes the popup, head to /home as a safety net
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

  // Bind
  const form = btn.closest("form");
  if (form) {
    form.addEventListener("submit", (e) => { e.preventDefault(); startFlow(); });
  }
  btn.addEventListener("click", (e) => { e.preventDefault(); startFlow(); });
})();